package http_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	adaptershttp "github.com/bnema/bitwarden-go-sdk/internal/adapters/http"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/testkit/bitwardenremote"
)

// -------- NewVaultClient tests --------

func TestNewVaultClient_EmptyURL(t *testing.T) {
	t.Parallel()
	_, err := adaptershttp.NewVaultClient("", http.DefaultClient, nopTokenProvider("tok"))
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewVaultClient_InvalidURL(t *testing.T) {
	t.Parallel()
	_, err := adaptershttp.NewVaultClient("://invalid", http.DefaultClient, nopTokenProvider("tok"))
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestNewVaultClient_NoHost(t *testing.T) {
	t.Parallel()
	_, err := adaptershttp.NewVaultClient("https://", http.DefaultClient, nopTokenProvider("tok"))
	if err == nil {
		t.Fatal("expected error for URL with no host")
	}
}

func TestNewVaultClient_BadScheme(t *testing.T) {
	t.Parallel()
	_, err := adaptershttp.NewVaultClient("ftp://vault.example.com", http.DefaultClient, nopTokenProvider("tok"))
	if err == nil {
		t.Fatal("expected error for ftp scheme")
	}
}

// -------- Sync tests --------

func TestSyncFetchesPersonalVaultUsingContractTestkit(t *testing.T) {
	t.Parallel()
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())
	tokenProvider := nopTokenProvider("test-access-token")

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	result, err := client.Sync(context.Background(), ports.SyncOptions{})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Assert profile mapped correctly.
	if result.Profile.ID != "user-id-1" {
		t.Errorf("expected Profile.ID=user-id-1, got %s", result.Profile.ID)
	}
	if result.Profile.Email != "user@example.com" {
		t.Errorf("expected Profile.Email=user@example.com, got %s", result.Profile.Email)
	}
	if result.Profile.Name != "Sanitized User" {
		t.Errorf("expected Profile.Name=Sanitized User, got %s", result.Profile.Name)
	}

	// Assert folders mapped correctly.
	if len(result.Folders) != 1 {
		t.Fatalf("expected 1 folder, got %d", len(result.Folders))
	}
	if result.Folders[0].ID != "folder-id-1" {
		t.Errorf("expected folder ID=folder-id-1, got %s", result.Folders[0].ID)
	}
	if result.Folders[0].Name != "2.sanitized-iv|sanitized-folder-name|sanitized-mac" {
		t.Errorf("unexpected folder name: %s", result.Folders[0].Name)
	}

	// Assert ciphers mapped correctly.
	if len(result.Ciphers) != 1 {
		t.Fatalf("expected 1 cipher, got %d", len(result.Ciphers))
	}
	if result.Ciphers[0].ID != "cipher-id-1" {
		t.Errorf("expected cipher ID=cipher-id-1, got %s", result.Ciphers[0].ID)
	}
	if result.Ciphers[0].Type != 1 {
		t.Errorf("expected cipher Type=1, got %d", result.Ciphers[0].Type)
	}
	if result.Ciphers[0].Name != "2.sanitized-iv|sanitized-name|sanitized-mac" {
		t.Errorf("unexpected cipher name: %s", result.Ciphers[0].Name)
	}
	if result.Ciphers[0].Favorite {
		t.Error("expected cipher Favorite=false, got true")
	}

	// Verify recorder saw the request.
	recorder := server.Recorder()
	if err := recorder.AssertRequest("GET", "/sync"); err != nil {
		t.Errorf("recorder: %v", err)
	}

	// Verify auth was present on the request.
	reqs := recorder.Requests()
	found := false
	for _, r := range reqs {
		if r.Path == "/sync" && r.AuthPresent {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected recorded /sync request with auth present")
	}
}

func TestSyncExcludeDomainsQuery(t *testing.T) {
	t.Parallel()
	// Use a custom httptest server that records the raw query.
	var capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sync" {
			capturedQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"Profile":{"Id":"id","Name":"n","Email":"e"},"Folders":[],"Ciphers":[]}`)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	_, err = client.Sync(context.Background(), ports.SyncOptions{ExcludeDomains: true})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if capturedQuery != "excludeDomains=true" {
		t.Errorf("expected query excludeDomains=true, got %q", capturedQuery)
	}
}

func TestSyncUnauthorizedMapsError(t *testing.T) {
	t.Parallel()
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario(bitwardenremote.WithExpiredAccessToken()))
	tokenProvider := nopTokenProvider("expired-token")

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	_, err = client.Sync(context.Background(), ports.SyncOptions{})
	if err == nil {
		t.Fatal("expected error for expired token")
	}

	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindUnauthenticated {
		t.Errorf("expected KindUnauthenticated, got %s", cerr.Kind)
	}
	if cerr.Status != http.StatusUnauthorized {
		t.Errorf("expected Status=401, got %d", cerr.Status)
	}
}

func TestSyncRateLimitMapsRetryAfter(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sync" {
			w.Header().Set("Retry-After", "15")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	_, err = client.Sync(context.Background(), ports.SyncOptions{})
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
	if cerr.RetryAfter != 15 {
		t.Errorf("expected RetryAfter=15, got %d", cerr.RetryAfter)
	}
	if cerr.Status != http.StatusTooManyRequests {
		t.Errorf("expected Status=429, got %d", cerr.Status)
	}
}

func TestSyncRejectsCrossOriginRedirect(t *testing.T) {
	t.Parallel()
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://evil.example.com/sync")
		w.WriteHeader(http.StatusFound)
	}))
	defer redirectSrv.Close()

	client, err := adaptershttp.NewVaultClient(redirectSrv.URL, http.DefaultClient, nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	_, err = client.Sync(context.Background(), ports.SyncOptions{})
	if err == nil {
		t.Fatal("expected error for cross-origin redirect")
	}
	if !strings.Contains(err.Error(), "redirect rejected") {
		t.Errorf("expected redirect rejected error, got: %v", err)
	}
}

// -------- Config tests --------

func TestConfig_Success(t *testing.T) {
	t.Parallel()
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	cfg, err := client.Config(context.Background())
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if cfg.Version != "test" {
		t.Errorf("expected Version=test, got %s", cfg.Version)
	}
	if cfg.FeatureFlags == nil {
		t.Error("expected non-nil FeatureFlags")
	}
}

func TestConfig_NonOK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	_, err = client.Config(context.Background())
	if err == nil {
		t.Fatal("expected error for non-200 config")
	}
	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindUnknown {
		t.Errorf("expected KindUnknown, got %s", cerr.Kind)
	}
}

// -------- AccountProfile tests --------

func TestAccountProfile_Success(t *testing.T) {
	t.Parallel()
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	profile, err := client.AccountProfile(context.Background())
	if err != nil {
		t.Fatalf("AccountProfile: %v", err)
	}
	if profile.ID != "user-id-1" {
		t.Errorf("expected ID=user-id-1, got %s", profile.ID)
	}
	if profile.Email != "user@example.com" {
		t.Errorf("expected Email=user@example.com, got %s", profile.Email)
	}
	if profile.Name != "Sanitized User" {
		t.Errorf("expected Name=Sanitized User, got %s", profile.Name)
	}
}

func TestAccountProfile_Unauthorized(t *testing.T) {
	t.Parallel()
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario(bitwardenremote.WithExpiredAccessToken()))

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	_, err = client.AccountProfile(context.Background())
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindUnauthenticated {
		t.Errorf("expected KindUnauthenticated, got %s", cerr.Kind)
	}
}

// -------- Subscription tests --------

func TestSubscription_Success(t *testing.T) {
	t.Parallel()
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	sub, err := client.Subscription(context.Background())
	if err != nil {
		t.Fatalf("Subscription: %v", err)
	}
	if sub.Plan == "" {
		t.Error("expected non-empty Plan")
	}
}

// -------- CreateCipher/UpdateCipher/DeleteCipher return unsupported --------

func TestCreateCipher_Unsupported(t *testing.T) {
	t.Parallel()
	client, err := adaptershttp.NewVaultClient("http://localhost:9999", http.DefaultClient, nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	_, err = client.CreateCipher(context.Background(), ports.EncryptedCipher{})
	if err == nil {
		t.Fatal("expected unsupported error")
	}
	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindUnsupported {
		t.Errorf("expected KindUnsupported, got %s", cerr.Kind)
	}
}

func TestUpdateCipher_Unsupported(t *testing.T) {
	t.Parallel()
	client, err := adaptershttp.NewVaultClient("http://localhost:9999", http.DefaultClient, nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	_, err = client.UpdateCipher(context.Background(), "id", ports.EncryptedCipher{})
	if err == nil {
		t.Fatal("expected unsupported error")
	}
	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindUnsupported {
		t.Errorf("expected KindUnsupported, got %s", cerr.Kind)
	}
}

func TestDeleteCipher_Unsupported(t *testing.T) {
	t.Parallel()
	client, err := adaptershttp.NewVaultClient("http://localhost:9999", http.DefaultClient, nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	err = client.DeleteCipher(context.Background(), "id")
	if err == nil {
		t.Fatal("expected unsupported error")
	}
	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindUnsupported {
		t.Errorf("expected KindUnsupported, got %s", cerr.Kind)
	}
}

// -------- Helpers --------

// nopTokenProvider returns a tokenProvider that always returns the given token string.
func nopTokenProvider(token string) func(context.Context) (ports.SecretBytes, error) {
	return func(_ context.Context) (ports.SecretBytes, error) {
		return ports.NewSecretBytes([]byte(token)), nil
	}
}
