package http_test

import (
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

// nopTokenProvider returns a tokenProvider that always returns the given token string.
func nopTokenProvider(token string) func(context.Context) (ports.SecretBytes, error) {
	return func(_ context.Context) (ports.SecretBytes, error) {
		return ports.NewSecretBytes([]byte(token)), nil
	}
}
