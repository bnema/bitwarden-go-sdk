package bitwardenremote

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	adaptershttp "github.com/bnema/bitwarden-go-sdk/internal/adapters/http"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// ---------------------------------------------------------------------------
// Prelogin
// ---------------------------------------------------------------------------

func TestAuthPreloginEndpoint(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	client := newIdentityClient(t, s.IdentityURL())

	result, err := client.Prelogin(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("Prelogin failed: %v", err)
	}

	// Verify KDF settings from the PBKDF2 fixture.
	if result.KDF.Type != "PBKDF2" {
		t.Errorf("expected KDF type PBKDF2, got %q", result.KDF.Type)
	}
	if result.KDF.Iterations != 600000 {
		t.Errorf("expected 600000 iterations, got %d", result.KDF.Iterations)
	}

	// Verify recorder metadata.
	if err := s.Recorder().AssertRequest("POST", "/accounts/prelogin/password"); err != nil {
		t.Fatalf("assert request: %v", err)
	}
	if err := s.Recorder().AssertContentType("/accounts/prelogin/password", "application/json; charset=utf-8"); err != nil {
		t.Fatalf("assert content type: %v", err)
	}

	// KnownFields should contain only structural key names.
	reqs := s.Recorder().Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 recorded request, got %d", len(reqs))
	}
	fields := reqs[0].KnownFields
	if len(fields) != 1 || fields[0] != "email" {
		t.Errorf("expected KnownFields=[\"email\"], got %v", fields)
	}
}

// ---------------------------------------------------------------------------
// Password token success (no 2FA)
// ---------------------------------------------------------------------------

func TestAuthPasswordTokenSuccess(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	client := newIdentityClient(t, s.IdentityURL())

	resp, err := client.LoginPassword(context.Background(), ports.PasswordTokenRequest{
		Email:            "user@example.com",
		AuthHash:         "test-auth-hash",
		DeviceType:       "desktop",
		DeviceIdentifier: "test-device-id",
		DeviceName:       "test-device",
	})
	if err != nil {
		t.Fatalf("LoginPassword failed: %v", err)
	}

	// Verify token response fields — SecretBytes is a value type so we check
	// that Bytes() returns a non-empty slice.
	if len(resp.Tokens.AccessToken.Bytes()) == 0 {
		t.Error("expected non-empty access token")
	}
	if len(resp.Tokens.RefreshToken.Bytes()) == 0 {
		t.Error("expected non-empty refresh token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected Bearer token type, got %q", resp.TokenType)
	}

	// Verify recorder.
	if err := s.Recorder().AssertRequest("POST", "/connect/token"); err != nil {
		t.Fatalf("assert request: %v", err)
	}
	if err := s.Recorder().AssertContentType("/connect/token", "application/x-www-form-urlencoded; charset=utf-8"); err != nil {
		t.Fatalf("assert content type: %v", err)
	}

	// Verify KnownFields contains only field names, not values.
	reqs := s.Recorder().Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 recorded request, got %d", len(reqs))
	}
	for _, f := range reqs[0].KnownFields {
		if f == "user@example.com" || f == "test-auth-hash" {
			t.Errorf("KnownFields contains a value, not a field name: %q", f)
		}
	}
}

// ---------------------------------------------------------------------------
// Two-factor challenge and completion
// ---------------------------------------------------------------------------

func TestAuthTwoFactorChallenge(t *testing.T) {
	s := NewServer(t, NewScenario(WithTwoFactorProvider("email")))
	defer s.Close()

	client := newIdentityClient(t, s.IdentityURL())

	// Step 1: LoginPassword should return 2FA required error.
	_, err := client.LoginPassword(context.Background(), ports.PasswordTokenRequest{
		Email:            "user@example.com",
		AuthHash:         "test-auth-hash",
		DeviceType:       "desktop",
		DeviceIdentifier: "test-device-id",
	})
	if err == nil {
		t.Fatal("expected 2FA required error, got nil")
	}

	// Verify it's a two-factor required error.
	if !coreerrors.Is(err, coreerrors.KindTwoFactorRequired) {
		t.Fatalf("expected KindTwoFactorRequired error, got: %v", err)
	}

	// Extract the structured error to check providers.
	var coreErr *coreerrors.Error
	if errors.As(err, &coreErr) {
		if len(coreErr.TwoFactorProviders) == 0 {
			t.Fatal("expected at least one TwoFactorProvider in error")
		}
	}

	// Verify the error lists the expected provider.
	if len(coreErr.TwoFactorProviders) == 0 {
		t.Fatal("expected at least one TwoFactorProvider in error")
	}
}

func TestAuthCompleteTwoFactor(t *testing.T) {
	s := NewServer(t, NewScenario(WithTwoFactorProvider("email")))
	defer s.Close()

	client := newIdentityClient(t, s.IdentityURL())

	// Complete two-factor with the 2FA token.
	resp, err := client.CompleteTwoFactor(context.Background(), ports.TwoFactorTokenRequest{
		Email:            "user@example.com",
		AuthHash:         "test-auth-hash",
		Provider:         ports.TwoFactorProviderEmail,
		Code:             "123456",
		Remember:         false,
		DeviceType:       "desktop",
		DeviceIdentifier: "test-device-id",
		DeviceName:       "test-device",
	})
	if err != nil {
		t.Fatalf("CompleteTwoFactor failed: %v", err)
	}

	if len(resp.Tokens.AccessToken.Bytes()) == 0 {
		t.Error("expected non-empty access token after 2FA completion")
	}

	// Verify recorder.
	if err := s.Recorder().AssertRequest("POST", "/connect/token"); err != nil {
		t.Fatalf("assert request: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Refresh token
// ---------------------------------------------------------------------------

func TestAuthRefresh(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	client := newIdentityClient(t, s.IdentityURL())

	resp, err := client.Refresh(context.Background(), ports.RefreshTokenRequest{
		ClientID:     "desktop",
		RefreshToken: ports.NewSecretBytes([]byte("test-refresh-token")),
	})
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	if len(resp.Tokens.AccessToken.Bytes()) == 0 {
		t.Error("expected non-empty access token after refresh")
	}
	if len(resp.Tokens.RefreshToken.Bytes()) == 0 {
		t.Error("expected non-empty refresh token after refresh")
	}

	if err := s.Recorder().AssertRequest("POST", "/connect/token"); err != nil {
		t.Fatalf("assert request: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Rate limit
// ---------------------------------------------------------------------------

func TestAuthRateLimit(t *testing.T) {
	s := NewServer(t, NewScenario(WithRateLimit(5)))
	defer s.Close()

	client := newIdentityClient(t, s.IdentityURL())

	_, err := client.LoginPassword(context.Background(), ports.PasswordTokenRequest{
		Email:            "user@example.com",
		AuthHash:         "test-auth-hash",
		DeviceType:       "desktop",
		DeviceIdentifier: "test-device-id",
	})
	if err == nil {
		t.Fatal("expected rate limit error, got nil")
	}

	if !coreerrors.Is(err, coreerrors.KindRateLimited) {
		t.Fatalf("expected KindRateLimited error, got: %v", err)
	}

	var coreErr *coreerrors.Error
	if errors.As(err, &coreErr) && coreErr.RetryAfter != 5 {
		t.Errorf("expected RetryAfter=5, got %d", coreErr.RetryAfter)
	}
}

// ---------------------------------------------------------------------------
// Recorder safety: no bodies or secrets stored
// ---------------------------------------------------------------------------

func TestAuthRecorderDoesNotStoreBodiesOrSecrets(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	// Use a raw HTTP client to send requests with sentinel values.
	rawClient := &http.Client{Timeout: 5 * time.Second}

	// Send a prelogin request with a sentinel email.
	preloginBody := `{"email":"SECRET_PASSWORD"}`
	req, err := http.NewRequest("POST", s.IdentityURL()+"/accounts/prelogin/password", strings.NewReader(preloginBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := rawClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Send a token request with sentinel values.
	tokenBody := "grant_type=password&username=user&password=SECRET_AUTH_HASH&scope=api+offline_access&client_id=desktop&deviceType=desktop&deviceIdentifier=id" +
		"&refresh_token=SECRET_REFRESH_TOKEN"
	req2, err := http.NewRequest("POST", s.IdentityURL()+"/connect/token", strings.NewReader(tokenBody))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	resp2, err := rawClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	// Verify KnownFields do NOT contain sentinel values.
	reqs := s.Recorder().Requests()
	for _, recReq := range reqs {
		for _, field := range recReq.KnownFields {
			if strings.Contains(field, "SECRET_PASSWORD") ||
				strings.Contains(field, "SECRET_AUTH_HASH") ||
				strings.Contains(field, "SECRET_REFRESH_TOKEN") {
				t.Errorf("KnownFields leaks secret value: %q", field)
			}
		}
	}

	// AssertNoRawBodies must pass because KnownFields store only field names.
	if err := s.Recorder().AssertNoRawBodies(); err != nil {
		t.Fatalf("AssertNoRawBodies failed: %v", err)
	}

	// Verify the recorder contains only field names (JSON keys / form keys).
	for _, recReq := range reqs {
		for _, field := range recReq.KnownFields {
			if field == "SECRET_PASSWORD" ||
				field == "SECRET_AUTH_HASH" ||
				field == "SECRET_REFRESH_TOKEN" {
				t.Errorf("secret value found in KnownFields: %q", field)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Rejection of wrong method or content type
// ---------------------------------------------------------------------------

func TestAuthRejectsWrongContentType(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	rawClient := &http.Client{Timeout: 5 * time.Second}

	// Correct method but wrong Content-Type.
	body := `{"email":"user@example.com"}`
	req, err := http.NewRequest("POST", s.IdentityURL()+"/accounts/prelogin/password", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := rawClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415 for wrong content type, got %d", resp.StatusCode)
	}
	defer func() { _ = resp.Body.Close() }()

	// Wrong method (GET instead of POST).
	req2, err := http.NewRequest("GET", s.IdentityURL()+"/accounts/prelogin/password", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := rawClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for wrong method, got %d", resp2.StatusCode)
	}
	defer func() { _ = resp2.Body.Close() }()
}

func TestAuthRejectsWrongTokenContentType(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	rawClient := &http.Client{Timeout: 5 * time.Second}

	// Correct method but wrong Content-Type for token endpoint.
	body := "grant_type=password"
	req, err := http.NewRequest("POST", s.IdentityURL()+"/connect/token", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := rawClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415 for wrong content type, got %d", resp.StatusCode)
	}
	defer func() { _ = resp.Body.Close() }()

	// Wrong method for token endpoint.
	req2, err := http.NewRequest("GET", s.IdentityURL()+"/connect/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := rawClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for wrong method, got %d", resp2.StatusCode)
	}
	defer func() { _ = resp2.Body.Close() }()
}

// ---------------------------------------------------------------------------
// Password grant: missing required fields → 400 invalid_grant
// ---------------------------------------------------------------------------

func TestAuthRejectsMissingPasswordGrantFields(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	base := s.IdentityURL()

	tests := []struct {
		name     string
		formBody string
	}{
		{name: "missing username", formBody: "grant_type=password&password=hash&scope=api&client_id=desktop"},
		{name: "missing password", formBody: "grant_type=password&username=user&scope=api&client_id=desktop"},
		{name: "missing scope", formBody: "grant_type=password&username=user&password=hash&client_id=desktop"},
		{name: "missing client_id", formBody: "grant_type=password&username=user&password=hash&scope=api"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", base+"/connect/token", strings.NewReader(tt.formBody))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", resp.StatusCode)
			}

			// Verify the body contains invalid_grant but not the field values.
			var body map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("expected JSON body: %v", err)
			}
			if body["error"] != "invalid_grant" {
				t.Errorf("expected error=invalid_grant, got %v", body["error"])
			}
			// Must not leak values in error.
			if desc, ok := body["error_description"].(string); ok {
				if strings.Contains(desc, "user") || strings.Contains(desc, "hash") {
					t.Errorf("error description leaks values: %q", desc)
				}
			}
		})
	}

	// Verify recorder has no body values.
	if err := s.Recorder().AssertNoRawBodies(); err != nil {
		t.Errorf("AssertNoRawBodies failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Refresh grant: missing required fields → 400 invalid_grant
// ---------------------------------------------------------------------------

func TestAuthRejectsMissingRefreshGrantFields(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	base := s.IdentityURL()

	tests := []struct {
		name     string
		formBody string
	}{
		{name: "missing refresh_token", formBody: "grant_type=refresh_token&client_id=desktop"},
		{name: "missing client_id", formBody: "grant_type=refresh_token&refresh_token=rtoken"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", base+"/connect/token", strings.NewReader(tt.formBody))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", resp.StatusCode)
			}

			var body map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("expected JSON body: %v", err)
			}
			if body["error"] != "invalid_grant" {
				t.Errorf("expected error=invalid_grant, got %v", body["error"])
			}
		})
	}

	if err := s.Recorder().AssertNoRawBodies(); err != nil {
		t.Errorf("AssertNoRawBodies failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newIdentityClient creates an IdentityClient pointing at the given URL.
func newIdentityClient(t testing.TB, baseURL string) *adaptershttp.IdentityClient {
	t.Helper()
	client, err := adaptershttp.NewIdentityClient(baseURL, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}
	return client
}
