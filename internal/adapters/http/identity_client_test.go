package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	adaptershttp "github.com/bnema/bitwarden-go-sdk/internal/adapters/http"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// -------- NewIdentityClient tests --------

func TestNewIdentityClient_EmptyURL(t *testing.T) {
	t.Parallel()
	_, err := adaptershttp.NewIdentityClient("", http.DefaultClient)
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewIdentityClient_InvalidURL(t *testing.T) {
	t.Parallel()
	_, err := adaptershttp.NewIdentityClient("://invalid", http.DefaultClient)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestNewIdentityClient_NoHost(t *testing.T) {
	t.Parallel()
	_, err := adaptershttp.NewIdentityClient("https://", http.DefaultClient)
	if err == nil {
		t.Fatal("expected error for URL with no host")
	}
}

func TestNewIdentityClient_BadScheme(t *testing.T) {
	t.Parallel()
	_, err := adaptershttp.NewIdentityClient("ftp://identity.example.com", http.DefaultClient)
	if err == nil {
		t.Fatal("expected error for ftp scheme")
	}
}

// -------- Prelogin tests --------

func TestPrelogin_Success_PBKDF2(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/accounts/prelogin/password" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Errorf("expected Content-Type application/json; charset=utf-8, got %s", ct)
		}
		if version := r.Header.Get("Bitwarden-Client-Version"); version != "0.1.0" {
			t.Errorf("expected Bitwarden-Client-Version=0.1.0, got %s", version)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["email"] != "user@example.com" {
			t.Errorf("unexpected email: %s", body["email"])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"Kdf":0,"KdfIterations":600000,"KdfMemory":0,"KdfParallelism":0}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	result, err := client.Prelogin(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("Prelogin: %v", err)
	}
	if result.KDF.Type != "PBKDF2" {
		t.Errorf("expected PBKDF2, got %s", result.KDF.Type)
	}
	if result.KDF.Iterations != 600000 {
		t.Errorf("expected 600000 iterations, got %d", result.KDF.Iterations)
	}
}

func TestPrelogin_Success_Argon2id(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"Kdf":1,"KdfIterations":3,"KdfMemory":64,"KdfParallelism":4}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	result, err := client.Prelogin(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("Prelogin: %v", err)
	}
	if result.KDF.Type != "Argon2id" {
		t.Errorf("expected Argon2id, got %s", result.KDF.Type)
	}
	if result.KDF.Iterations != 3 {
		t.Errorf("expected 3 iterations, got %d", result.KDF.Iterations)
	}
	if result.KDF.MemoryMiB != 64 {
		t.Errorf("expected 64 MiB memory, got %d", result.KDF.MemoryMiB)
	}
	if result.KDF.Parallelism != 4 {
		t.Errorf("expected 4 parallel, got %d", result.KDF.Parallelism)
	}
}

func TestPrelogin_NonOKStatus(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	_, err = client.Prelogin(context.Background(), "user@example.com")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindUnknown {
		t.Errorf("expected KindUnknown, got %s", cerr.Kind)
	}
	if cerr.Status != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", cerr.Status)
	}
}

// -------- LoginPassword tests --------

func TestLoginPassword_Success(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/connect/token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded; charset=utf-8" {
			t.Errorf("expected application/x-www-form-urlencoded; charset=utf-8, got %s", ct)
		}
		if version := r.Header.Get("Bitwarden-Client-Version"); version != "0.1.0" {
			t.Errorf("expected Bitwarden-Client-Version=0.1.0, got %s", version)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "password" {
			t.Errorf("expected grant_type=password, got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("username") != "user@example.com" {
			t.Errorf("expected username=user@example.com, got %s", r.Form.Get("username"))
		}
		if r.Form.Get("scope") != "api offline_access" {
			t.Errorf("expected scope 'api offline_access', got %s", r.Form.Get("scope"))
		}
		if r.Form.Get("client_id") != "desktop" {
			t.Errorf("expected client_id=desktop, got %s", r.Form.Get("client_id"))
		}
		if r.Form.Get("deviceType") != "Chrome" {
			t.Errorf("expected deviceType=Chrome, got %s", r.Form.Get("deviceType"))
		}
		if r.Form.Get("deviceIdentifier") != "device-abc" {
			t.Errorf("expected deviceIdentifier=device-abc, got %s", r.Form.Get("deviceIdentifier"))
		}
		if r.Form.Get("deviceName") != "" {
			t.Errorf("expected no deviceName, got %s", r.Form.Get("deviceName"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"access_token":"at1","refresh_token":"rt1","token_type":"Bearer","expires_in":3600,"Key":"encrypted-key-data","AccountId":"acct-1"}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	resp, err := client.LoginPassword(context.Background(), ports.PasswordTokenRequest{
		Email:            "user@example.com",
		AuthHash:         "hash123",
		DeviceType:       "Chrome",
		DeviceIdentifier: "device-abc",
	})
	if err != nil {
		t.Fatalf("LoginPassword: %v", err)
	}
	if resp.AccountID != "acct-1" {
		t.Errorf("expected AccountID=acct-1, got %s", resp.AccountID)
	}
	if resp.EncryptedUserKey != "encrypted-key-data" {
		t.Errorf("expected Key=encrypted-key-data, got %s", resp.EncryptedUserKey)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %s", resp.TokenType)
	}
	if resp.ExpiresInSeconds != 3600 {
		t.Errorf("expected expires_in=3600, got %d", resp.ExpiresInSeconds)
	}
	at := resp.Tokens.AccessToken.Bytes()
	if string(at) != "at1" {
		t.Errorf("expected access_token=at1, got %s", string(at))
	}
	rt := resp.Tokens.RefreshToken.Bytes()
	if string(rt) != "rt1" {
		t.Errorf("expected refresh_token=rt1, got %s", string(rt))
	}
	if resp.Tokens.TokenType != "Bearer" {
		t.Errorf("expected TokenType=Bearer, got %s", resp.Tokens.TokenType)
	}
	if resp.Tokens.ExpiresAt.IsZero() {
		t.Error("expected non-zero ExpiresAt")
	}
}

func TestLoginPassword_WithDeviceName(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.Form.Get("deviceName") != "My-Desktop" {
			t.Errorf("expected deviceName=My-Desktop, got %s", r.Form.Get("deviceName"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600,"Key":"k"}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	_, err = client.LoginPassword(context.Background(), ports.PasswordTokenRequest{
		Email:            "user@example.com",
		AuthHash:         "hash123",
		DeviceType:       "Chrome",
		DeviceIdentifier: "device-abc",
		DeviceName:       "My-Desktop",
	})
	if err != nil {
		t.Fatalf("LoginPassword: %v", err)
	}
}

func TestLoginPassword_InvalidGrant(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Invalid credentials."}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	_, err = client.LoginPassword(context.Background(), ports.PasswordTokenRequest{
		Email:    "user@example.com",
		AuthHash: "bad-hash",
	})
	if err == nil {
		t.Fatal("expected error for invalid_grant")
	}
	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindUnauthenticated {
		t.Errorf("expected KindUnauthenticated, got %s", cerr.Kind)
	}
	if cerr.Code != "invalid_grant" {
		t.Errorf("expected code invalid_grant, got %s", cerr.Code)
	}
}

func TestLoginPassword_TwoFactorRequired(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders2":{"0":null,"1":null}}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	_, err = client.LoginPassword(context.Background(), ports.PasswordTokenRequest{
		Email:    "user@example.com",
		AuthHash: "hash",
	})
	if err == nil {
		t.Fatal("expected error for 2FA required")
	}
	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindTwoFactorRequired {
		t.Errorf("expected KindTwoFactorRequired, got %s", cerr.Kind)
	}
	if cerr.Code != "two_factor_required" {
		t.Errorf("expected code two_factor_required, got %s", cerr.Code)
	}
	if len(cerr.TwoFactorProviders) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(cerr.TwoFactorProviders))
	}
	hasAuth := false
	hasEmail := false
	for _, p := range cerr.TwoFactorProviders {
		if p == "authenticator" {
			hasAuth = true
		}
		if p == "email" {
			hasEmail = true
		}
	}
	if !hasAuth {
		t.Error("expected authenticator provider")
	}
	if !hasEmail {
		t.Error("expected email provider")
	}
}

func TestLoginPassword_RateLimited(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, `{"error":"too_many_requests"}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	_, err = client.LoginPassword(context.Background(), ports.PasswordTokenRequest{
		Email:    "user@example.com",
		AuthHash: "hash",
	})
	if err == nil {
		t.Fatal("expected error for rate limit")
	}
	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindRateLimited {
		t.Errorf("expected KindRateLimited, got %s", cerr.Kind)
	}
	if cerr.RetryAfter != 30 {
		t.Errorf("expected RetryAfter=30, got %d", cerr.RetryAfter)
	}
}

func TestLoginPassword_AccountIDFromAccessTokenSubject(t *testing.T) {
	t.Parallel()
	accessToken := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhY2N0LWZyb20tdG9rZW4ifQ."
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"rt","token_type":"Bearer","expires_in":3600,"Key":"k"}`, accessToken)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	resp, err := client.LoginPassword(context.Background(), ports.PasswordTokenRequest{
		Email:    "user@example.com",
		AuthHash: "hash",
	})
	if err != nil {
		t.Fatalf("LoginPassword: %v", err)
	}
	if resp.AccountID != "acct-from-token" {
		t.Errorf("expected AccountID from token subject, got %q", resp.AccountID)
	}
}

// -------- CompleteTwoFactor tests --------

func TestTokenResponseLeavesAccountIDEmptyWhenTokenHasNoSubject(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600,"Key":"k"}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	resp, err := client.LoginPassword(context.Background(), ports.PasswordTokenRequest{Email: "user@example.com", AuthHash: "hash"})
	if err != nil {
		t.Fatalf("LoginPassword: %v", err)
	}
	if resp.AccountID != "" {
		t.Errorf("expected empty AccountID, got %q", resp.AccountID)
	}
}

func TestCompleteTwoFactor_Success(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/connect/token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if version := r.Header.Get("Bitwarden-Client-Version"); version != "0.1.0" {
			t.Errorf("expected Bitwarden-Client-Version=0.1.0, got %s", version)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "password" {
			t.Errorf("expected grant_type=password, got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("twoFactorToken") != "123456" {
			t.Errorf("expected twoFactorToken=123456, got %s", r.Form.Get("twoFactorToken"))
		}
		if r.Form.Get("twoFactorProvider") != "1" {
			t.Errorf("expected twoFactorProvider=1 (email), got %s", r.Form.Get("twoFactorProvider"))
		}
		if r.Form.Get("twoFactorRemember") != "1" {
			t.Errorf("expected twoFactorRemember=1, got %s", r.Form.Get("twoFactorRemember"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"access_token":"at2fa","refresh_token":"rt2fa","token_type":"Bearer","expires_in":3600,"Key":"key2fa","AccountId":"acct-2"}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	resp, err := client.CompleteTwoFactor(context.Background(), ports.TwoFactorTokenRequest{
		Email:            "user@example.com",
		AuthHash:         "hash123",
		Provider:         ports.TwoFactorProviderEmail,
		Code:             "123456",
		Remember:         true,
		DeviceType:       "Chrome",
		DeviceIdentifier: "device-abc",
	})
	if err != nil {
		t.Fatalf("CompleteTwoFactor: %v", err)
	}
	at := resp.Tokens.AccessToken.Bytes()
	if string(at) != "at2fa" {
		t.Errorf("expected access_token=at2fa, got %s", string(at))
	}
	if resp.AccountID != "acct-2" {
		t.Errorf("expected AccountID=acct-2, got %s", resp.AccountID)
	}
}

func TestCompleteTwoFactor_NotRemember(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.Form.Get("twoFactorRemember") != "0" {
			t.Errorf("expected twoFactorRemember=0, got %s", r.Form.Get("twoFactorRemember"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600,"Key":"k"}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	_, err = client.CompleteTwoFactor(context.Background(), ports.TwoFactorTokenRequest{
		Email:            "user@example.com",
		AuthHash:         "hash",
		Provider:         ports.TwoFactorProviderAuthenticator,
		Code:             "654321",
		Remember:         false,
		DeviceType:       "Chrome",
		DeviceIdentifier: "device-abc",
	})
	if err != nil {
		t.Fatalf("CompleteTwoFactor: %v", err)
	}
}

func TestCompleteTwoFactor_ProviderMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		provider ports.TwoFactorProvider
		want     string
	}{
		{ports.TwoFactorProviderAuthenticator, "0"},
		{ports.TwoFactorProviderEmail, "1"},
		{ports.TwoFactorProviderDuo, "2"},
		{ports.TwoFactorProviderYubiKey, "3"},
	}

	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Fatalf("parse form: %v", err)
				}
				if got := r.Form.Get("twoFactorProvider"); got != tt.want {
					t.Errorf("expected twoFactorProvider=%s, got %s", tt.want, got)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprint(w, `{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600,"Key":"k"}`)
			}))
			defer srv.Close()

			client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
			if err != nil {
				t.Fatalf("NewIdentityClient: %v", err)
			}

			_, err = client.CompleteTwoFactor(context.Background(), ports.TwoFactorTokenRequest{
				Email:            "user@example.com",
				AuthHash:         "hash",
				Provider:         tt.provider,
				Code:             "000000",
				Remember:         false,
				DeviceType:       "Chrome",
				DeviceIdentifier: "device-abc",
			})
			if err != nil {
				t.Fatalf("CompleteTwoFactor: %v", err)
			}
		})
	}
}

// -------- Refresh tests --------

func TestRefresh_Success(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/connect/token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("expected grant_type=refresh_token, got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("client_id") != "desktop" {
			t.Errorf("expected client_id=desktop, got %s", r.Form.Get("client_id"))
		}
		if r.Form.Get("refresh_token") != "old-rt" {
			t.Errorf("expected refresh_token=old-rt, got %s", r.Form.Get("refresh_token"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"access_token":"new-at","refresh_token":"new-rt","token_type":"Bearer","expires_in":3600,"Key":"new-key","AccountId":"acct-1"}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	resp, err := client.Refresh(context.Background(), ports.RefreshTokenRequest{
		AccountID:    "acct-1",
		RefreshToken: ports.NewSecretBytes([]byte("old-rt")),
	})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	at := resp.Tokens.AccessToken.Bytes()
	if string(at) != "new-at" {
		t.Errorf("expected access_token=new-at, got %s", string(at))
	}
	rt := resp.Tokens.RefreshToken.Bytes()
	if string(rt) != "new-rt" {
		t.Errorf("expected refresh_token=new-rt, got %s", string(rt))
	}
}

func TestRefresh_InvalidGrant(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Refresh token expired."}`)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	_, err = client.Refresh(context.Background(), ports.RefreshTokenRequest{
		RefreshToken: ports.NewSecretBytes([]byte("expired-rt")),
	})
	if err == nil {
		t.Fatal("expected error for invalid_grant on refresh")
	}
	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindUnauthenticated {
		t.Errorf("expected KindUnauthenticated, got %s", cerr.Kind)
	}
}

// -------- Cross-origin redirect tests --------

func TestCrossOriginRedirect_Rejected(t *testing.T) {
	t.Parallel()
	// First request returns a redirect to a different host.
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://evil.example.com/connect/token")
		w.WriteHeader(http.StatusFound)
	}))
	defer redirectSrv.Close()

	client, err := adaptershttp.NewIdentityClient(redirectSrv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	_, err = client.Prelogin(context.Background(), "user@example.com")
	if err == nil {
		t.Fatal("expected error for cross-origin redirect")
	}
	if !strings.Contains(err.Error(), "redirect rejected") {
		t.Errorf("expected redirect rejected error, got: %v", err)
	}
}

func TestCrossOriginRedirect_TokenEndpoint_Rejected(t *testing.T) {
	t.Parallel()
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://evil.example.com/connect/token")
		w.WriteHeader(http.StatusFound)
	}))
	defer redirectSrv.Close()

	client, err := adaptershttp.NewIdentityClient(redirectSrv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	_, err = client.LoginPassword(context.Background(), ports.PasswordTokenRequest{
		Email:    "user@example.com",
		AuthHash: "hash",
	})
	if err == nil {
		t.Fatal("expected error for cross-origin redirect")
	}
	if !strings.Contains(err.Error(), "redirect rejected") {
		t.Errorf("expected redirect rejected error, got: %v", err)
	}
}

func TestSameOriginRedirect_Allowed(t *testing.T) {
	t.Parallel()
	// Prelogin endpoint on the same origin returns a 302 to another path
	// on the same host, which then returns the JSON response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/accounts/prelogin/password" {
			// Redirect to a different path on the same host.
			http.Redirect(w, r, "/kdf-response", http.StatusFound)
			return
		}
		if r.URL.Path == "/kdf-response" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"Kdf":0,"KdfIterations":600000,"KdfMemory":0,"KdfParallelism":0}`)
			return
		}
		t.Errorf("unexpected path: %s", r.URL.Path)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	result, err := client.Prelogin(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("Prelogin: %v", err)
	}
	if result.KDF.Type != "PBKDF2" {
		t.Errorf("expected PBKDF2, got %s", result.KDF.Type)
	}
}

// -------- context cancellation test --------

func TestPrelogin_CancelledContext(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	client, err := adaptershttp.NewIdentityClient(srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.Prelogin(ctx, "user@example.com")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}
