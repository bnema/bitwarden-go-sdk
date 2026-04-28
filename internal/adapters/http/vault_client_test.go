package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

func TestAccountProfileUsingContractTestkit(t *testing.T) {
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
	if !profile.EmailVerified {
		t.Error("expected EmailVerified=true")
	}
	if !profile.Premium {
		t.Error("expected Premium=true")
	}
	if profile.PremiumFromOrganization {
		t.Error("expected PremiumFromOrganization=false")
	}
	if profile.Culture != "en-US" {
		t.Errorf("expected Culture=en-US, got %s", profile.Culture)
	}
	if !profile.TwoFactorEnabled {
		t.Error("expected TwoFactorEnabled=true")
	}
	if profile.ForcePasswordReset {
		t.Error("expected ForcePasswordReset=false")
	}
	if profile.UsesKeyConnector {
		t.Error("expected UsesKeyConnector=false")
	}
	if !profile.VerifyDevices {
		t.Error("expected VerifyDevices=true")
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

func TestAccountSubscriptionUsingContractTestkit(t *testing.T) {
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
	if sub.StorageName == "" {
		t.Error("expected non-empty StorageName")
	}
	if sub.StorageGB <= 0 {
		t.Errorf("expected StorageGB > 0, got %d", sub.StorageGB)
	}
	if sub.MaxStorageGB <= 0 {
		t.Errorf("expected MaxStorageGB > 0, got %d", sub.MaxStorageGB)
	}

	// Verify auth was present on the request.
	recorder := server.Recorder()
	reqs := recorder.Requests()
	found := false
	for _, r := range reqs {
		if r.Path == "/accounts/subscription" && r.AuthPresent {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected recorded /accounts/subscription request with auth")
	}
}

func TestSubscription_Unauthorized(t *testing.T) {
	t.Parallel()
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario(bitwardenremote.WithExpiredAccessToken()))

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	_, err = client.Subscription(context.Background())
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

// -------- Cipher write operations using contract testkit --------

func TestCipherCreateUpdateTrashRestoreDeleteUsingContractTestkit(t *testing.T) {
	t.Parallel()

	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())
	tokenProvider := nopTokenProvider("test-access-token")

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	// Use the same test CipherID from the fixture.
	cipherID := "cipher-id-1"

	t.Run("CreateCipher", func(t *testing.T) {
		input := ports.EncryptedCipher{
			Type: 1,
			Name: "2.sanitized-iv|sanitized-name|sanitized-mac",
			Login: &ports.EncryptedLoginCipher{
				Username: "enc-username",
				Password: "enc-password",
			},
		}
		created, err := client.CreateCipher(context.Background(), input)
		if err != nil {
			t.Fatalf("CreateCipher: %v", err)
		}
		if created.ID == "" {
			t.Error("expected non-empty ID in created cipher")
		}
		if created.Type != 1 {
			t.Errorf("expected Type=1, got %d", created.Type)
		}
		if created.Name == "" {
			t.Error("expected non-empty Name in created cipher")
		}

		// Verify recorder saw the request with auth and JSON fields.
		recorder := server.Recorder()
		if err := recorder.AssertRequest("POST", "/ciphers"); err != nil {
			t.Errorf("recorder: %v", err)
		}
		reqs := recorder.Requests()
		found := false
		for _, r := range reqs {
			if r.Path == "/ciphers" && r.Method == "POST" && r.AuthPresent {
				found = true
				if len(r.KnownFields) == 0 {
					t.Error("expected KnownFields in request body")
				}
				break
			}
		}
		if !found {
			t.Error("expected recorded POST /ciphers request with auth")
		}
	})

	t.Run("UpdateCipher", func(t *testing.T) {
		input := ports.EncryptedCipher{
			Type: 1,
			Name: "2.sanitized-iv|sanitized-updated-name|sanitized-mac",
		}
		updated, err := client.UpdateCipher(context.Background(), cipherID, input)
		if err != nil {
			t.Fatalf("UpdateCipher: %v", err)
		}
		if updated.ID == "" {
			t.Error("expected non-empty ID in updated cipher")
		}

		recorder := server.Recorder()
		if err := recorder.AssertRequest("PUT", "/ciphers/"+cipherID); err != nil {
			t.Errorf("recorder: %v", err)
		}
		reqs := recorder.Requests()
		found := false
		for _, r := range reqs {
			if r.Path == "/ciphers/"+cipherID && r.Method == "PUT" && r.AuthPresent {
				found = true
				if len(r.KnownFields) == 0 {
					t.Error("expected KnownFields in request body")
				}
				break
			}
		}
		if !found {
			t.Error("expected recorded PUT /ciphers/{id} request with auth")
		}
	})

	t.Run("TrashCipher", func(t *testing.T) {
		err := client.TrashCipher(context.Background(), cipherID)
		if err != nil {
			t.Fatalf("TrashCipher: %v", err)
		}

		recorder := server.Recorder()
		if err := recorder.AssertRequest("PUT", "/ciphers/"+cipherID+"/delete"); err != nil {
			t.Errorf("recorder: %v", err)
		}
		reqs := recorder.Requests()
		found := false
		for _, r := range reqs {
			if r.Path == "/ciphers/"+cipherID+"/delete" && r.Method == "PUT" && r.AuthPresent {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected recorded PUT /ciphers/{id}/delete request with auth")
		}
	})

	t.Run("RestoreCipher", func(t *testing.T) {
		restored, err := client.RestoreCipher(context.Background(), cipherID)
		if err != nil {
			t.Fatalf("RestoreCipher: %v", err)
		}
		if restored.ID == "" {
			t.Error("expected non-empty ID in restored cipher")
		}

		recorder := server.Recorder()
		if err := recorder.AssertRequest("PUT", "/ciphers/"+cipherID+"/restore"); err != nil {
			t.Errorf("recorder: %v", err)
		}
		reqs := recorder.Requests()
		found := false
		for _, r := range reqs {
			if r.Path == "/ciphers/"+cipherID+"/restore" && r.Method == "PUT" && r.AuthPresent {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected recorded PUT /ciphers/{id}/restore request with auth")
		}
	})

	t.Run("DeleteCipher", func(t *testing.T) {
		err := client.DeleteCipher(context.Background(), cipherID)
		if err != nil {
			t.Fatalf("DeleteCipher: %v", err)
		}

		recorder := server.Recorder()
		if err := recorder.AssertRequest("DELETE", "/ciphers/"+cipherID); err != nil {
			t.Errorf("recorder: %v", err)
		}
		reqs := recorder.Requests()
		found := false
		for _, r := range reqs {
			if r.Path == "/ciphers/"+cipherID && r.Method == "DELETE" && r.AuthPresent {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected recorded DELETE /ciphers/{id} request with auth")
		}
	})
}

// -------- Folder tests using contract testkit --------

func TestFolderListCreateUpdateDeleteUsingContractTestkit(t *testing.T) {
	t.Parallel()

	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())
	tokenProvider := nopTokenProvider("test-access-token")

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	folderID := "folder-id-1"

	t.Run("ListFolders", func(t *testing.T) {
		folders, err := client.ListFolders(context.Background())
		if err != nil {
			t.Fatalf("ListFolders: %v", err)
		}
		if len(folders) == 0 {
			t.Fatal("expected at least one folder")
		}
		found := false
		for _, f := range folders {
			if f.ID == folderID {
				found = true
				if f.Name == "" {
					t.Error("expected non-empty folder name")
				}
				break
			}
		}
		if !found {
			t.Errorf("expected folder %q in list", folderID)
		}

		recorder := server.Recorder()
		if err := recorder.AssertRequest("GET", "/folders"); err != nil {
			t.Errorf("recorder: %v", err)
		}
		reqs := recorder.Requests()
		foundReq := false
		for _, r := range reqs {
			if r.Path == "/folders" && r.Method == "GET" && r.AuthPresent {
				foundReq = true
				break
			}
		}
		if !foundReq {
			t.Error("expected recorded GET /folders request with auth")
		}
	})

	t.Run("CreateFolder", func(t *testing.T) {
		input := ports.EncryptedFolder{
			Name: "2.sanitized-iv|sanitized-folder-name|sanitized-mac",
		}
		created, err := client.CreateFolder(context.Background(), input)
		if err != nil {
			t.Fatalf("CreateFolder: %v", err)
		}
		if created.ID == "" {
			t.Error("expected non-empty ID in created folder")
		}
		if created.Name == "" {
			t.Error("expected non-empty Name in created folder")
		}

		recorder := server.Recorder()
		if err := recorder.AssertRequest("POST", "/folders"); err != nil {
			t.Errorf("recorder: %v", err)
		}
		reqs := recorder.Requests()
		found := false
		for _, r := range reqs {
			if r.Path == "/folders" && r.Method == "POST" && r.AuthPresent {
				found = true
				if len(r.KnownFields) == 0 {
					t.Error("expected KnownFields in request body")
				}
				break
			}
		}
		if !found {
			t.Error("expected recorded POST /folders request with auth")
		}
	})

	t.Run("UpdateFolder", func(t *testing.T) {
		input := ports.EncryptedFolder{
			Name: "2.sanitized-iv|sanitized-updated-folder-name|sanitized-mac",
		}
		updated, err := client.UpdateFolder(context.Background(), folderID, input)
		if err != nil {
			t.Fatalf("UpdateFolder: %v", err)
		}
		if updated.ID == "" {
			t.Error("expected non-empty ID in updated folder")
		}

		recorder := server.Recorder()
		if err := recorder.AssertRequest("PUT", "/folders/"+folderID); err != nil {
			t.Errorf("recorder: %v", err)
		}
		reqs := recorder.Requests()
		found := false
		for _, r := range reqs {
			if r.Path == "/folders/"+folderID && r.Method == "PUT" && r.AuthPresent {
				found = true
				if len(r.KnownFields) == 0 {
					t.Error("expected KnownFields in request body")
				}
				break
			}
		}
		if !found {
			t.Error("expected recorded PUT /folders/{id} request with auth")
		}
	})

	t.Run("DeleteFolder", func(t *testing.T) {
		err := client.DeleteFolder(context.Background(), folderID)
		if err != nil {
			t.Fatalf("DeleteFolder: %v", err)
		}

		recorder := server.Recorder()
		if err := recorder.AssertRequest("DELETE", "/folders/"+folderID); err != nil {
			t.Errorf("recorder: %v", err)
		}
		reqs := recorder.Requests()
		found := false
		for _, r := range reqs {
			if r.Path == "/folders/"+folderID && r.Method == "DELETE" && r.AuthPresent {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected recorded DELETE /folders/{id} request with auth")
		}
	})
}

// -------- Request DTO serialisation checks --------

func TestCreateCipherRequestUsesMappedRequestDTO(t *testing.T) {
	t.Parallel()

	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ciphers" && r.Method == http.MethodPost {
			var err error
			capturedBody, err = io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"Id":"new-id","Type":1,"Name":"n","Favorite":false}`)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	input := ports.EncryptedCipher{
		Type: 1,
		Name: "2.iv|enc-name|mac",
		Login: &ports.EncryptedLoginCipher{
			Username: "enc-user",
			Password: "enc-pass",
		},
	}

	_, err = client.CreateCipher(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateCipher: %v", err)
	}

	if len(capturedBody) == 0 {
		t.Fatal("no request body captured")
	}

	var raw map[string]any
	if err := json.Unmarshal(capturedBody, &raw); err != nil {
		t.Fatalf("unmarshal captured body: %v", err)
	}

	// Must contain lower-camel keys.
	camelKeys := []string{"type", "name", "favorite", "login"}
	for _, k := range camelKeys {
		if _, ok := raw[k]; !ok {
			t.Errorf("expected lower-camel key %q in request body", k)
		}
	}

	// Must NOT contain PascalCase keys.
	pascalKeys := []string{"Type", "Name", "Favorite", "Login"}
	for _, k := range pascalKeys {
		if _, ok := raw[k]; ok {
			t.Errorf("unexpected PascalCase key %q in request body — should be lower-camel", k)
		}
	}

	// Verify login sub-object uses lower-camel keys.
	loginRaw, ok := raw["login"].(map[string]any)
	if !ok {
		t.Fatal("expected login sub-object")
	}
	camelLoginKeys := []string{"username", "password"}
	for _, k := range camelLoginKeys {
		if _, ok := loginRaw[k]; !ok {
			t.Errorf("expected lower-camel key %q in login sub-object", k)
		}
	}
	pascalLoginKeys := []string{"Username", "Password"}
	for _, k := range pascalLoginKeys {
		if _, ok := loginRaw[k]; ok {
			t.Errorf("unexpected PascalCase key %q in login sub-object", k)
		}
	}
}

func TestUpdateCipherRequestUsesMappedRequestDTO(t *testing.T) {
	t.Parallel()

	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ciphers/test-id" && r.Method == http.MethodPut {
			var err error
			capturedBody, err = io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"Id":"test-id","Type":1,"Name":"n","Favorite":false}`)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	input := ports.EncryptedCipher{
		Type: 1,
		Name: "2.iv|enc-name|mac",
	}

	_, err = client.UpdateCipher(context.Background(), "test-id", input)
	if err != nil {
		t.Fatalf("UpdateCipher: %v", err)
	}

	if len(capturedBody) == 0 {
		t.Fatal("no request body captured")
	}

	var raw map[string]any
	if err := json.Unmarshal(capturedBody, &raw); err != nil {
		t.Fatalf("unmarshal captured body: %v", err)
	}

	camelKeys := []string{"type", "name", "favorite"}
	for _, k := range camelKeys {
		if _, ok := raw[k]; !ok {
			t.Errorf("expected lower-camel key %q in request body", k)
		}
	}

	pascalKeys := []string{"Type", "Name", "Favorite"}
	for _, k := range pascalKeys {
		if _, ok := raw[k]; ok {
			t.Errorf("unexpected PascalCase key %q in request body — should be lower-camel", k)
		}
	}
}

// -------- Escaped ID tests --------

func TestUpdateCipherEscapesIDPathSegment(t *testing.T) {
	t.Parallel()

	var capturedRawQuery string
	var capturedRawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			capturedRawQuery = r.URL.RawQuery
			capturedRawPath = r.URL.RawPath
			if capturedRawPath == "" {
				capturedRawPath = r.URL.Path
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"Id":"escaped-id","Type":1,"Name":"n","Favorite":false}`)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	input := ports.EncryptedCipher{
		Type: 1,
		Name: "enc-name",
	}

	// Use an ID with special characters that must be percent-encoded.
	dangerID := "abc/../x?bad=1"
	_, err = client.UpdateCipher(context.Background(), dangerID, input)
	if err != nil {
		t.Fatalf("UpdateCipher: %v", err)
	}

	// The query string must be empty — the ? in the ID must be escaped.
	if capturedRawQuery != "" {
		t.Errorf("expected empty RawQuery, got %q — the ? in the ID was not escaped", capturedRawQuery)
	}

	// The raw path must contain percent-encoded characters so the ID is
	// transmitted as a single segment.
	expectedFragment := url.PathEscape(dangerID)
	if !strings.Contains(capturedRawPath, expectedFragment) {
		t.Errorf("expected raw path to contain %q, got %q", expectedFragment, capturedRawPath)
	}
}

func TestUpdateFolderEscapesIDPathSegment(t *testing.T) {
	t.Parallel()

	var capturedRawQuery string
	var capturedRawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			capturedRawQuery = r.URL.RawQuery
			capturedRawPath = r.URL.RawPath
			if capturedRawPath == "" {
				capturedRawPath = r.URL.Path
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"Id":"escaped-fid","Name":"n"}`)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	input := ports.EncryptedFolder{
		Name: "enc-folder",
	}

	dangerID := "abc/../x?bad=1"
	_, err = client.UpdateFolder(context.Background(), dangerID, input)
	if err != nil {
		t.Fatalf("UpdateFolder: %v", err)
	}

	// The query string must be empty — the ? in the ID must be escaped.
	if capturedRawQuery != "" {
		t.Errorf("expected empty RawQuery, got %q — the ? in the ID was not escaped", capturedRawQuery)
	}

	// The raw path must contain percent-encoded characters so the ID is
	// transmitted as a single segment.
	expectedFragment := url.PathEscape(dangerID)
	if !strings.Contains(capturedRawPath, expectedFragment) {
		t.Errorf("expected raw path to contain %q, got %q", expectedFragment, capturedRawPath)
	}
}

// -------- Folder request JSON tests --------

func TestCreateFolderRequestUsesLowerCamelName(t *testing.T) {
	t.Parallel()

	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/folders" && r.Method == http.MethodPost {
			var err error
			capturedBody, err = io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"Id":"new-folder-id","Name":"n"}`)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	input := ports.EncryptedFolder{Name: "enc-folder-name"}
	_, err = client.CreateFolder(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	if len(capturedBody) == 0 {
		t.Fatal("no request body captured")
	}

	var raw map[string]any
	if err := json.Unmarshal(capturedBody, &raw); err != nil {
		t.Fatalf("unmarshal captured body: %v", err)
	}

	// Must contain lower-camel "name" key.
	if _, ok := raw["name"]; !ok {
		t.Errorf("expected lower-camel key %q in folder create request body", "name")
	}

	// Must NOT contain PascalCase "Name".
	if _, ok := raw["Name"]; ok {
		t.Errorf("unexpected PascalCase key %q in folder create request body — should be lower-camel", "Name")
	}
}

func TestUpdateFolderRequestUsesLowerCamelName(t *testing.T) {
	t.Parallel()

	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/folders/") {
			var err error
			capturedBody, err = io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"Id":"updated-folder-id","Name":"n"}`)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	input := ports.EncryptedFolder{Name: "enc-folder-updated"}
	_, err = client.UpdateFolder(context.Background(), "test-fid", input)
	if err != nil {
		t.Fatalf("UpdateFolder: %v", err)
	}

	if len(capturedBody) == 0 {
		t.Fatal("no request body captured")
	}

	var raw map[string]any
	if err := json.Unmarshal(capturedBody, &raw); err != nil {
		t.Fatalf("unmarshal captured body: %v", err)
	}

	// Must contain lower-camel "name" key.
	if _, ok := raw["name"]; !ok {
		t.Errorf("expected lower-camel key %q in folder update request body", "name")
	}

	// Must NOT contain PascalCase "Name".
	if _, ok := raw["Name"]; ok {
		t.Errorf("unexpected PascalCase key %q in folder update request body — should be lower-camel", "Name")
	}
}

// -------- Helpers --------

// -------- Attachment tests --------

func TestAttachmentMetadataUsingContractTestkit(t *testing.T) {
	t.Parallel()

	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())
	tokenProvider := nopTokenProvider("test-access-token")

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	meta, err := client.GetAttachment(context.Background(), "cipher-id-1", "attachment-id-1")
	if err != nil {
		t.Fatalf("GetAttachment: %v", err)
	}

	if meta.ID != "attachment-id-1" {
		t.Errorf("expected ID=attachment-id-1, got %s", meta.ID)
	}
	if meta.FileName == "" {
		t.Error("expected non-empty FileName")
	}
	if meta.Size != 128 {
		t.Errorf("expected Size=128, got %d", meta.Size)
	}

	recorder := server.Recorder()
	if err := recorder.AssertRequest("GET", "/ciphers/cipher-id-1/attachment/attachment-id-1"); err != nil {
		t.Errorf("recorder: %v", err)
	}
}

func TestAttachmentInitDirectUsingContractTestkit(t *testing.T) {
	t.Parallel()

	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario(bitwardenremote.WithDirectAttachmentUpload()))
	tokenProvider := nopTokenProvider("test-access-token")

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	req := ports.AttachmentUploadRequest{
		CipherID: "cipher-id-1",
		FileName: "2.sanitized-iv|sanitized-file-name|sanitized-mac",
		Key:      "2.sanitized-iv|sanitized-attachment-key|sanitized-mac",
		FileSize: 128,
	}

	resp, err := client.InitAttachmentUpload(context.Background(), req)
	if err != nil {
		t.Fatalf("InitAttachmentUpload: %v", err)
	}

	if resp.AttachmentID != "attachment-id-1" {
		t.Errorf("expected AttachmentID=attachment-id-1, got %s", resp.AttachmentID)
	}
	if resp.FileUploadType != 0 {
		t.Errorf("expected FileUploadType=0 (direct), got %d", resp.FileUploadType)
	}

	recorder := server.Recorder()
	if err := recorder.AssertRequest("POST", "/ciphers/cipher-id-1/attachment/v2"); err != nil {
		t.Errorf("recorder: %v", err)
	}
}

func TestAttachmentDirectUploadUsesMultipartDataField(t *testing.T) {
	t.Parallel()

	var capturedContentType string
	var capturedFormField string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/attachment/") {
			capturedContentType = r.Header.Get("Content-Type")

			// Parse the multipart form to verify the field name is "data".
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				http.Error(w, "bad multipart", http.StatusBadRequest)
				return
			}
			for name := range r.MultipartForm.File {
				// file fields — ignore
				_ = name
			}
			for name := range r.MultipartForm.Value {
				capturedFormField = name
			}

			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	content := strings.NewReader("test content bytes")
	err = client.UploadAttachmentDirect(context.Background(), "cipher-1", "att-1", content)
	if err != nil {
		t.Fatalf("UploadAttachmentDirect: %v", err)
	}

	if !strings.Contains(capturedContentType, "multipart/form-data") {
		t.Errorf("expected multipart/form-data content type, got %s", capturedContentType)
	}
	if capturedFormField != "data" {
		t.Errorf("expected form field name 'data', got %q", capturedFormField)
	}
}

func TestAttachmentExternalUploadUsesReturnedURL(t *testing.T) {
	t.Parallel()

	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario(bitwardenremote.WithExternalAttachmentUpload()))
	tokenProvider := nopTokenProvider("test-access-token")

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	// Init attachment upload to get the external URL.
	req := ports.AttachmentUploadRequest{
		CipherID: "cipher-id-1",
		FileName: "2.sanitized-iv|sanitized-file-name|sanitized-mac",
		Key:      "2.sanitized-iv|sanitized-attachment-key|sanitized-mac",
		FileSize: 32,
	}

	initResp, err := client.InitAttachmentUpload(context.Background(), req)
	if err != nil {
		t.Fatalf("InitAttachmentUpload: %v", err)
	}

	if initResp.URL == "" {
		t.Fatal("expected non-empty external upload URL")
	}

	// Upload content to the returned URL.
	content := strings.NewReader("test-content-for-external-upload")
	err = client.UploadAttachmentExternal(context.Background(), initResp.URL, content)
	if err != nil {
		t.Fatalf("UploadAttachmentExternal: %v", err)
	}

	// Verify the external upload was recorded.
	recorder := server.Recorder()
	// The external upload goes to the self-contained URL on the test server.
	found := false
	for _, r := range recorder.Requests() {
		if strings.HasPrefix(r.Path, "/external-attachment-upload/") && r.Method == "PUT" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected recorded PUT to /external-attachment-upload/ path")
	}
}

func TestAttachmentRenewAndDeleteUsingContractTestkit(t *testing.T) {
	t.Parallel()

	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())
	tokenProvider := nopTokenProvider("test-access-token")

	client, err := adaptershttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	cipherID := "cipher-id-1"
	attachmentID := "attachment-id-1"

	t.Run("RenewAttachmentUploadURL", func(t *testing.T) {
		resp, err := client.RenewAttachmentUploadURL(context.Background(), cipherID, attachmentID)
		if err != nil {
			t.Fatalf("RenewAttachmentUploadURL: %v", err)
		}
		if resp.AttachmentID != attachmentID {
			t.Errorf("expected AttachmentID=%s, got %s", attachmentID, resp.AttachmentID)
		}

		recorder := server.Recorder()
		path := "/ciphers/" + cipherID + "/attachment/" + attachmentID + "/renew"
		if err := recorder.AssertRequest("GET", path); err != nil {
			t.Errorf("recorder: %v", err)
		}
	})

	t.Run("DeleteAttachment", func(t *testing.T) {
		cipher, err := client.DeleteAttachment(context.Background(), cipherID, attachmentID)
		if err != nil {
			t.Fatalf("DeleteAttachment: %v", err)
		}
		if cipher.ID != cipherID {
			t.Errorf("expected Cipher.ID=%s, got %s", cipherID, cipher.ID)
		}

		recorder := server.Recorder()
		path := "/ciphers/" + cipherID + "/attachment/" + attachmentID
		if err := recorder.AssertRequest("DELETE", path); err != nil {
			t.Errorf("recorder: %v", err)
		}
	})
}

func TestAttachmentEscapesIDs(t *testing.T) {
	t.Parallel()

	var capturedRawQuery string
	var capturedRawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRawQuery = r.URL.RawQuery
		capturedRawPath = r.URL.RawPath
		if capturedRawPath == "" {
			capturedRawPath = r.URL.Path
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Id":"att-1","FileName":"n","Key":"k","Size":0,"SizeName":""}`))
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	dangerID := "abc/../x?bad=1"
	_, err = client.GetAttachment(context.Background(), dangerID, "att-1")
	if err != nil {
		t.Fatalf("GetAttachment: %v", err)
	}

	if capturedRawQuery != "" {
		t.Errorf("expected empty RawQuery, got %q — the ? in the ID was not escaped", capturedRawQuery)
	}

	expectedFragment := url.PathEscape(dangerID)
	if !strings.Contains(capturedRawPath, expectedFragment) {
		t.Errorf("expected raw path to contain %q, got %q", expectedFragment, capturedRawPath)
	}
}

func TestDownloadAttachmentSuccess(t *testing.T) {
	t.Parallel()

	wantBody := []byte("attachment binary content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(wantBody)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	reader, err := client.DownloadAttachment(context.Background(), srv.URL+"/download")
	if err != nil {
		t.Fatalf("DownloadAttachment: %v", err)
	}
	defer func() { _ = reader.Close() }()

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(got, wantBody) {
		t.Errorf("body mismatch: got %x, want %x", got, wantBody)
	}
}

func TestDownloadAttachmentRejectsNonHTTPS(t *testing.T) {
	t.Parallel()

	client, err := adaptershttp.NewVaultClient("https://example.com", http.DefaultClient, nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	_, err = client.DownloadAttachment(context.Background(), "ftp://evil.example.com/file")
	if err == nil {
		t.Fatal("expected error for non-http/https URL")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("expected error mentioning scheme, got: %v", err)
	}
}

func TestDownloadAttachmentNon200ClosesBodyAndReturnsError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found body"))
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	_, err = client.DownloadAttachment(context.Background(), srv.URL+"/missing")
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	var cerr *coreerrors.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *coreerrors.Error, got %T", err)
	}
	if cerr.Kind != coreerrors.KindUnknown {
		t.Errorf("expected KindUnknown, got %s", cerr.Kind)
	}
	if cerr.Status != http.StatusNotFound {
		t.Errorf("expected Status=404, got %d", cerr.Status)
	}
}

func TestAttachmentUploadRejectsBadExternalURL(t *testing.T) {
	t.Parallel()

	client, err := adaptershttp.NewVaultClient("https://example.com", http.DefaultClient, nopTokenProvider("tok"))
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	err = client.UploadAttachmentExternal(context.Background(), "ftp://malicious.example.com/file", strings.NewReader("data"))
	if err == nil {
		t.Fatal("expected error for non-http/https external URL")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("expected error message mentioning scheme, got: %v", err)
	}
}

func TestUploadAttachmentDirectTokenErrorDoesNotStartPipe(t *testing.T) {
	t.Parallel()

	// tokenProvider that always fails.
	tokenErr := errors.New("token provider unavailable")
	tokenProvider := func(_ context.Context) (ports.SecretBytes, error) {
		return ports.SecretBytes{}, tokenErr
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), tokenProvider)
	if err != nil {
		t.Fatalf("NewVaultClient: %v", err)
	}

	// A blocking reader that never returns — if the goroutine were started
	// before auth failed, this would hang indefinitely.
	blockingReader := &blockingReader{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.UploadAttachmentDirect(ctx, "c1", "a1", blockingReader)
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error from token provider")
		}
		if !strings.Contains(err.Error(), "token provider") {
			t.Errorf("expected token provider error, got: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("UploadAttachmentDirect blocked/hung — goroutine/pipe was started before auth")
	}
}

// blockingReader blocks on Read forever (simulates a slow/blocking content source).
type blockingReader struct{}

func (b *blockingReader) Read(_ []byte) (int, error) {
	select {} // never returns
}

// -------- Helpers --------

// nopTokenProvider returns a tokenProvider that always returns the given token string.
func nopTokenProvider(token string) func(context.Context) (ports.SecretBytes, error) {
	return func(_ context.Context) (ports.SecretBytes, error) {
		return ports.NewSecretBytes([]byte(token)), nil
	}
}
