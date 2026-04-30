package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/adapters/http/dto"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// IdentityClient implements ports.IdentityClient by calling the Bitwarden
// identity server over HTTP.
type IdentityClient struct {
	baseURL string
	client  *http.Client
}

// NewIdentityClient creates an IdentityClient that sends requests to the
// given baseIdentityURL. The provided client is cloned so its CheckRedirect
// can be set to reject cross-origin redirects.
func NewIdentityClient(baseIdentityURL string, client *http.Client) (*IdentityClient, error) {
	if baseIdentityURL == "" {
		return nil, fmt.Errorf("identity URL must not be empty")
	}
	parsedURL, err := url.Parse(baseIdentityURL)
	if err != nil {
		return nil, fmt.Errorf("invalid identity URL %q: %w", baseIdentityURL, err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("identity URL %q must have http or https scheme", baseIdentityURL)
	}
	if parsedURL.Host == "" {
		return nil, fmt.Errorf("identity URL %q must have a host", baseIdentityURL)
	}

	cloned := &http.Client{
		Transport: client.Transport,
		Timeout:   client.Timeout,
		Jar:       client.Jar,
	}
	cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		orig := via[0].URL
		if req.URL.Scheme != orig.Scheme || req.URL.Host != orig.Host {
			return fmt.Errorf("redirect rejected from %s://%s to %s://%s", orig.Scheme, orig.Host, req.URL.Scheme, req.URL.Host)
		}
		return nil
	}

	return &IdentityClient{
		baseURL: strings.TrimRight(baseIdentityURL, "/"),
		client:  cloned,
	}, nil
}

// Prelogin sends a prelogin request for the given email and returns KDF
// settings from the server.
func (c *IdentityClient) Prelogin(ctx context.Context, email string) (ports.PreloginResult, error) {
	body := dto.PreloginRequest{Email: email}
	payload, err := json.Marshal(body)
	if err != nil {
		return ports.PreloginResult{}, fmt.Errorf("marshal prelogin request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/accounts/prelogin/password", bytes.NewReader(payload))
	if err != nil {
		return ports.PreloginResult{}, fmt.Errorf("create prelogin request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	setBitwardenClientHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.PreloginResult{}, fmt.Errorf("prelogin request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.PreloginResult{}, c.parseErrorResponse(resp)
	}

	var preloginResp dto.PreloginResponse
	if err := json.NewDecoder(resp.Body).Decode(&preloginResp); err != nil {
		return ports.PreloginResult{}, fmt.Errorf("decode prelogin response: %w", err)
	}

	return ports.PreloginResult{
		KDF: ports.KDFConfig{
			Type:        kdfTypeFromInt(preloginResp.Kdf),
			Iterations:  preloginResp.KdfIterations,
			MemoryMiB:   preloginResp.KdfMemory,
			Parallelism: preloginResp.KdfParallelism,
		},
	}, nil
}

// LoginPassword exchanges a master-password auth hash for OAuth tokens.
func (c *IdentityClient) LoginPassword(ctx context.Context, req ports.PasswordTokenRequest) (ports.TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", req.Email)
	form.Set("password", req.AuthHash)
	form.Set("scope", "api offline_access")
	form.Set("client_id", "desktop")
	form.Set("deviceType", req.DeviceType)
	form.Set("deviceIdentifier", req.DeviceIdentifier)
	if req.DeviceName != "" {
		form.Set("deviceName", req.DeviceName)
	}
	return c.doTokenRequest(ctx, form)
}

// CompleteTwoFactor continues a password login with a classic two-factor
// authentication token.
func (c *IdentityClient) CompleteTwoFactor(ctx context.Context, req ports.TwoFactorTokenRequest) (ports.TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", req.Email)
	form.Set("password", req.AuthHash)
	form.Set("scope", "api offline_access")
	form.Set("client_id", "desktop")
	form.Set("deviceType", req.DeviceType)
	form.Set("deviceIdentifier", req.DeviceIdentifier)
	if req.DeviceName != "" {
		form.Set("deviceName", req.DeviceName)
	}
	form.Set("twoFactorToken", req.Code)
	form.Set("twoFactorProvider", strconv.Itoa(providerToNumeric(req.Provider)))
	if req.Remember {
		form.Set("twoFactorRemember", "1")
	} else {
		form.Set("twoFactorRemember", "0")
	}
	return c.doTokenRequest(ctx, form)
}

// Refresh exchanges a refresh token for new OAuth tokens.
func (c *IdentityClient) Refresh(ctx context.Context, req ports.RefreshTokenRequest) (ports.TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	clientID := req.ClientID
	if clientID == "" {
		clientID = "desktop"
	}
	form.Set("client_id", clientID)
	form.Set("refresh_token", string(req.RefreshToken.Bytes()))
	return c.doTokenRequest(ctx, form)
}

// doTokenRequest sends a form-urlencoded POST to /connect/token and parses
// the response.
func (c *IdentityClient) doTokenRequest(ctx context.Context, form url.Values) (ports.TokenResponse, error) {
	payload := form.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/connect/token", strings.NewReader(payload))
	if err != nil {
		return ports.TokenResponse{}, fmt.Errorf("create token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	httpReq.Header.Set("Accept", "application/json")
	setBitwardenClientHeaders(httpReq)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return ports.TokenResponse{}, fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.TokenResponse{}, c.parseTokenErrorResponse(resp)
	}

	// Drain body before decoding to ensure no leak.
	var tokenResp dto.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return ports.TokenResponse{}, fmt.Errorf("decode token response: %w", err)
	}

	return ports.TokenResponse{
		Tokens: ports.TokenSet{
			AccessToken:  ports.NewSecretBytes([]byte(tokenResp.AccessToken)),
			RefreshToken: ports.NewSecretBytes([]byte(tokenResp.RefreshToken)),
			TokenType:    tokenResp.TokenType,
			ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		},
		AccountID:        tokenResp.AccountID,
		EncryptedUserKey: tokenResp.Key,
		TokenType:        tokenResp.TokenType,
		ExpiresInSeconds: tokenResp.ExpiresIn,
	}, nil
}

// parseErrorResponse handles error responses for non-token endpoints (e.g.
// prelogin). It checks for Retry-After headers for rate limiting.
func (c *IdentityClient) parseErrorResponse(resp *http.Response) error {
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		seconds, err := strconv.Atoi(retryAfter)
		if err == nil && seconds > 0 {
			return &coreerrors.Error{
				Kind:       coreerrors.KindRateLimited,
				Status:     resp.StatusCode,
				RetryAfter: seconds,
			}
		}
	}

	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	return &coreerrors.Error{
		Kind:   coreerrors.KindUnknown,
		Status: resp.StatusCode,
	}
}

// parseTokenErrorResponse handles error responses from /connect/token.
// It maps invalid_grant to KindUnauthenticated, presence of
// TwoFactorProviders2 to KindTwoFactorRequired, and Retry-After headers
// to KindRateLimited.
func (c *IdentityClient) parseTokenErrorResponse(resp *http.Response) error {
	// Check for Retry-After header (rate limiting).
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		seconds, err := strconv.Atoi(retryAfter)
		if err == nil && seconds > 0 {
			return &coreerrors.Error{
				Kind:       coreerrors.KindRateLimited,
				Status:     resp.StatusCode,
				RetryAfter: seconds,
			}
		}
	}

	// Try to parse the JSON error body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &coreerrors.Error{
			Kind:   coreerrors.KindUnknown,
			Status: resp.StatusCode,
		}
	}

	var errResp dto.TokenErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil || errResp.Error == "" {
		return &coreerrors.Error{
			Kind:   coreerrors.KindUnknown,
			Status: resp.StatusCode,
		}
	}

	// Two-factor required response.
	if errResp.Error == "invalid_grant" && len(errResp.TwoFactorProviders2) > 0 {
		providers := make([]string, 0, len(errResp.TwoFactorProviders2))
		for k := range errResp.TwoFactorProviders2 {
			if name := numericToProviderName(k); name != "" {
				providers = append(providers, name)
			}
		}
		return &coreerrors.Error{
			Kind:               coreerrors.KindTwoFactorRequired,
			Code:               "two_factor_required",
			TwoFactorProviders: providers,
		}
	}

	// Invalid credentials.
	if errResp.Error == "invalid_grant" {
		return &coreerrors.Error{
			Kind:    coreerrors.KindUnauthenticated,
			Code:    "invalid_grant",
			Message: errResp.ErrorDescription,
		}
	}

	return &coreerrors.Error{
		Kind:    coreerrors.KindUnknown,
		Status:  resp.StatusCode,
		Code:    errResp.Error,
		Message: errResp.ErrorDescription,
	}
}

// kdfTypeFromInt maps the numeric KDF identifier to a string. 0 = PBKDF2,
// 1 = Argon2id.
func kdfTypeFromInt(kdf int) string {
	switch kdf {
	case 0:
		return "PBKDF2"
	case 1:
		return "Argon2id"
	default:
		return "Unknown"
	}
}

// providerToNumeric maps a TwoFactorProvider to its numeric form value.
func providerToNumeric(p ports.TwoFactorProvider) int {
	switch p {
	case ports.TwoFactorProviderAuthenticator:
		return 0
	case ports.TwoFactorProviderEmail:
		return 1
	case ports.TwoFactorProviderDuo:
		return 2
	case ports.TwoFactorProviderYubiKey:
		return 3
	default:
		return 0
	}
}

// numericToProviderName maps a provider number string to its canonical name.
func numericToProviderName(numeric string) string {
	switch numeric {
	case "0":
		return "authenticator"
	case "1":
		return "email"
	case "2":
		return "duo"
	case "3":
		return "yubikey"
	default:
		return ""
	}
}
