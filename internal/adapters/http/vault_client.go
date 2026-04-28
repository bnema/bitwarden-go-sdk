package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bnema/bitwarden-go-sdk/internal/adapters/http/dto"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// VaultClient implements ports.APIClient by calling the Bitwarden API over
// HTTP.
type VaultClient struct {
	baseURL       string
	client        *http.Client
	tokenProvider func(context.Context) (ports.SecretBytes, error)
}

// NewVaultClient creates a VaultClient that sends requests to the given
// baseAPIURL. The provided client is cloned so its CheckRedirect can be set
// to reject cross-origin redirects. The tokenProvider is called on each
// request to supply the Bearer token.
func NewVaultClient(baseAPIURL string, client *http.Client, tokenProvider func(context.Context) (ports.SecretBytes, error)) (*VaultClient, error) {
	if baseAPIURL == "" {
		return nil, fmt.Errorf("api URL must not be empty")
	}
	parsedURL, err := url.Parse(baseAPIURL)
	if err != nil {
		return nil, fmt.Errorf("invalid api URL %q: %w", baseAPIURL, err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("api URL %q must have http or https scheme", baseAPIURL)
	}
	if parsedURL.Host == "" {
		return nil, fmt.Errorf("api URL %q must have a host", baseAPIURL)
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

	return &VaultClient{
		baseURL:       strings.TrimRight(baseAPIURL, "/"),
		client:        cloned,
		tokenProvider: tokenProvider,
	}, nil
}

// ---------------------------------------------------------------------------
// APIClient interface implementation
// ---------------------------------------------------------------------------

// Sync fetches the user's vault data.
func (c *VaultClient) Sync(ctx context.Context, opts ports.SyncOptions) (ports.SyncResult, error) {
	u := c.baseURL + "/sync"
	if opts.ExcludeDomains {
		u += "?excludeDomains=true"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ports.SyncResult{}, fmt.Errorf("create sync request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.SyncResult{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.SyncResult{}, fmt.Errorf("sync request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.SyncResult{}, c.parseErrorResponse(resp)
	}

	var syncResp dto.SyncResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return ports.SyncResult{}, fmt.Errorf("decode sync response: %w", err)
	}

	return c.mapSyncResult(syncResp), nil
}

// Config fetches server configuration.
func (c *VaultClient) Config(ctx context.Context) (ports.ServerConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/config", nil)
	if err != nil {
		return ports.ServerConfig{}, fmt.Errorf("create config request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.ServerConfig{}, fmt.Errorf("config request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.ServerConfig{}, c.parseErrorResponse(resp)
	}

	var cfg dto.ConfigResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return ports.ServerConfig{}, fmt.Errorf("decode config response: %w", err)
	}

	return ports.ServerConfig{
		Version:      cfg.Version,
		FeatureFlags: cfg.FeatureFlags,
		ServerName:   cfg.ServerName,
	}, nil
}

// AccountProfile fetches the user's account profile.
func (c *VaultClient) AccountProfile(ctx context.Context) (ports.AccountProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/accounts/profile", nil)
	if err != nil {
		return ports.AccountProfile{}, fmt.Errorf("create account profile request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.AccountProfile{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.AccountProfile{}, fmt.Errorf("account profile request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.AccountProfile{}, c.parseErrorResponse(resp)
	}

	var profile dto.AccountProfileResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return ports.AccountProfile{}, fmt.Errorf("decode account profile response: %w", err)
	}

	return ports.AccountProfile{
		ID:    profile.ID,
		Email: profile.Email,
		Name:  profile.Name,
	}, nil
}

// Subscription fetches the user's subscription information.
func (c *VaultClient) Subscription(ctx context.Context) (ports.Subscription, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/plans/subscription", nil)
	if err != nil {
		return ports.Subscription{}, fmt.Errorf("create subscription request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.Subscription{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.Subscription{}, fmt.Errorf("subscription request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.Subscription{}, c.parseErrorResponse(resp)
	}

	var sub dto.SubscriptionResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&sub); err != nil {
		return ports.Subscription{}, fmt.Errorf("decode subscription response: %w", err)
	}

	return ports.Subscription{
		Plan:      sub.StorageName,
		IsPremium: sub.StorageName != "" && sub.StorageName != "Free",
	}, nil
}

// CreateCipher creates a new cipher. Not yet supported.
func (c *VaultClient) CreateCipher(_ context.Context, _ ports.EncryptedCipher) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, &coreerrors.Error{
		Kind: coreerrors.KindUnsupported,
		Op:   "CreateCipher",
	}
}

// UpdateCipher updates an existing cipher. Not yet supported.
func (c *VaultClient) UpdateCipher(_ context.Context, _ string, _ ports.EncryptedCipher) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, &coreerrors.Error{
		Kind: coreerrors.KindUnsupported,
		Op:   "UpdateCipher",
	}
}

// DeleteCipher deletes a cipher. Not yet supported.
func (c *VaultClient) DeleteCipher(_ context.Context, _ string) error {
	return &coreerrors.Error{
		Kind: coreerrors.KindUnsupported,
		Op:   "DeleteCipher",
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// setAuthHeader calls the token provider and sets the Authorization header.
func (c *VaultClient) setAuthHeader(ctx context.Context, req *http.Request) error {
	token, err := c.tokenProvider(ctx)
	if err != nil {
		return fmt.Errorf("token provider: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+string(token.Bytes()))
	return nil
}

// parseErrorResponse handles error responses for vault API endpoints.
// It checks for Retry-After headers for rate limiting and maps 401 to
// KindUnauthenticated.
func (c *VaultClient) parseErrorResponse(resp *http.Response) error {
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

	// Drain body — do not read or log the content.
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return &coreerrors.Error{
			Kind:   coreerrors.KindUnauthenticated,
			Status: resp.StatusCode,
		}
	default:
		return &coreerrors.Error{
			Kind:   coreerrors.KindUnknown,
			Status: resp.StatusCode,
		}
	}
}

// mapSyncResult converts a DTO sync response into the port SyncResult.
func (c *VaultClient) mapSyncResult(s dto.SyncResponseDTO) ports.SyncResult {
	result := ports.SyncResult{
		Profile: ports.AccountProfile{
			ID:    s.Profile.ID,
			Email: s.Profile.Email,
			Name:  s.Profile.Name,
		},
		Folders: make([]ports.EncryptedFolder, 0, len(s.Folders)),
		Ciphers: make([]ports.EncryptedCipher, 0, len(s.Ciphers)),
	}

	for _, f := range s.Folders {
		result.Folders = append(result.Folders, ports.EncryptedFolder{
			ID:   f.ID,
			Name: f.Name,
		})
	}

	for _, ct := range s.Ciphers {
		cipher := ports.EncryptedCipher{
			ID:       ct.ID,
			Type:     ct.Type,
			Name:     ct.Name,
			Favorite: ct.Favorite,
		}
		if ct.Notes != nil {
			cipher.Notes = *ct.Notes
		}
		if ct.FolderID != nil {
			cipher.FolderID = *ct.FolderID
		}

		if ct.Login != nil {
			login := &ports.EncryptedLoginCipher{
				Username: ct.Login.Username,
				Password: ct.Login.Password,
				TOTP:     ct.Login.TOTP,
				URIs:     make([]ports.EncryptedLoginURI, 0, len(ct.Login.URIs)),
			}
			for _, u := range ct.Login.URIs {
				uri := ports.EncryptedLoginURI{
					URI:         u.URI,
					URIChecksum: u.URIChecksum,
				}
				if u.Match != nil {
					uri.Match = *u.Match
				}
				login.URIs = append(login.URIs, uri)
			}
			cipher.Login = login
		}

		if ct.SecureNote != nil {
			cipher.SecureNote = &ports.EncryptedSecureNoteCipher{
				Type: ct.SecureNote.Type,
			}
		}

		if ct.Card != nil {
			cipher.Card = &ports.EncryptedCardCipher{
				CardholderName: ct.Card.CardholderName,
				Brand:          ct.Card.Brand,
				Number:         ct.Card.Number,
				ExpMonth:       ct.Card.ExpMonth,
				ExpYear:        ct.Card.ExpYear,
				Code:           ct.Card.Code,
			}
		}

		if ct.Identity != nil {
			cipher.Identity = &ports.EncryptedIdentityCipher{
				Title:          ct.Identity.Title,
				FirstName:      ct.Identity.FirstName,
				MiddleName:     ct.Identity.MiddleName,
				LastName:       ct.Identity.LastName,
				Address1:       ct.Identity.Address1,
				Address2:       ct.Identity.Address2,
				Address3:       ct.Identity.Address3,
				City:           ct.Identity.City,
				State:          ct.Identity.State,
				PostalCode:     ct.Identity.PostalCode,
				Country:        ct.Identity.Country,
				Company:        ct.Identity.Company,
				Email:          ct.Identity.Email,
				Phone:          ct.Identity.Phone,
				SSN:            ct.Identity.SSN,
				Username:       ct.Identity.Username,
				PassportNumber: ct.Identity.PassportNumber,
				LicenseNumber:  ct.Identity.LicenseNumber,
			}
		}

		if len(ct.Fields) > 0 {
			cipher.Fields = make([]ports.EncryptedCipherField, 0, len(ct.Fields))
			for _, field := range ct.Fields {
				cipher.Fields = append(cipher.Fields, ports.EncryptedCipherField{
					Name:     field.Name,
					Value:    field.Value,
					Type:     field.Type,
					LinkedID: field.LinkedID,
				})
			}
		}

		result.Ciphers = append(result.Ciphers, cipher)
	}

	return result
}

// Ensure compile-time check that VaultClient implements ports.APIClient.
var _ ports.APIClient = (*VaultClient)(nil)
