package bitwardenremote

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Authorization required (no auth → 401)
// ---------------------------------------------------------------------------

func TestVaultRequiresAuthorization(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	// Endpoints that require auth; /config should be excluded.
	authEndpoints := []struct {
		method string
		path   string
		body   string
	}{
		{method: "GET", path: "/accounts/profile", body: ""},
		{method: "GET", path: "/sync", body: ""},
		{method: "GET", path: "/sync/revision-date", body: ""},
		{method: "POST", path: "/ciphers", body: `{"type":1}`},
		{method: "PUT", path: "/ciphers/abc-123", body: `{"type":1}`},
		{method: "DELETE", path: "/ciphers/abc-123", body: ""},
		{method: "PUT", path: "/ciphers/abc-123/restore", body: ""},
		{method: "POST", path: "/ciphers/abc-123/restore", body: ""},
		{method: "POST", path: "/ciphers/delete", body: `{"ids":["abc"]}`},
		{method: "GET", path: "/folders", body: ""},
		{method: "POST", path: "/folders", body: `{"name":"test"}`},
		{method: "PUT", path: "/folders/abc-123", body: `{"name":"test"}`},
		{method: "DELETE", path: "/folders/abc-123", body: ""},
		{method: "POST", path: "/ciphers/abc-123/attachment/v2", body: `{"fileName":"test.txt","fileSize":128}`},
		{method: "POST", path: "/ciphers/abc-123/attachment", body: `{"fileName":"test.txt","fileSize":128}`},
		{method: "DELETE", path: "/ciphers/abc-123/attachment/att-1", body: ""},
	}

	// /config should be accessible without auth
	configResp, err := http.Get(s.IdentityURL() + "/config")
	if err != nil {
		t.Fatal(err)
	}
	if configResp.StatusCode != http.StatusOK {
		t.Errorf("expected /config to return 200 without auth, got %d", configResp.StatusCode)
	}
	_ = configResp.Body.Close()

	for _, ep := range authEndpoints {
		req, err := http.NewRequest(ep.method, s.IdentityURL()+ep.path, strings.NewReader(ep.body))
		if err != nil {
			t.Fatal(err)
		}
		if ep.body != "" {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s: expected 401, got %d", ep.method, ep.path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// Expired access token → 401
// ---------------------------------------------------------------------------

func TestVaultExpiredAccessToken(t *testing.T) {
	s := NewServer(t, NewScenario(WithExpiredAccessToken()))
	defer s.Close()

	// Pick a few representative endpoints.
	ep := []struct {
		method string
		path   string
		body   string
	}{
		{method: "GET", path: "/accounts/profile", body: ""},
		{method: "GET", path: "/sync", body: ""},
		{method: "POST", path: "/ciphers", body: `{"type":1}`},
		{method: "PUT", path: "/ciphers/abc", body: `{"type":1}`},
		{method: "DELETE", path: "/ciphers/abc", body: ""},
		{method: "GET", path: "/folders", body: ""},
	}

	for _, ep := range ep {
		req, err := http.NewRequest(ep.method, s.IdentityURL()+ep.path, strings.NewReader(ep.body))
		if err != nil {
			t.Fatal(err)
		}
		if ep.body != "" {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}
		req.Header.Set("Authorization", "Bearer any-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s: expected 401 (expired token), got %d", ep.method, ep.path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// Account and sync fixtures return correct JSON and are recorded with auth
// ---------------------------------------------------------------------------

func TestVaultAccountAndSyncFixtures(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	client := &http.Client{}
	bearer := "Bearer test-access-token"

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{name: "account profile", method: "GET", path: "/accounts/profile", body: ""},
		{name: "sync", method: "GET", path: "/sync", body: ""},
		{name: "sync/revision-date", method: "GET", path: "/sync/revision-date", body: ""},
	}

	for _, tt := range tests {
		req, err := http.NewRequest(tt.method, s.IdentityURL()+tt.path, strings.NewReader(tt.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", bearer)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", tt.name, resp.StatusCode)
		}

		// Verify response is valid JSON.
		var raw any
		if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
			t.Errorf("%s: response is not valid JSON: %v", tt.name, err)
		}
		_ = resp.Body.Close()
	}

	// Verify all three requests were recorded with authPresent=true.
	reqs := s.Recorder().Requests()
	seen := map[string]bool{"/accounts/profile": false, "/sync": false, "/sync/revision-date": false}
	for _, r := range reqs {
		if _, ok := seen[r.Path]; ok {
			seen[r.Path] = true
			if !r.AuthPresent {
				t.Errorf("request to %s: expected AuthPresent=true", r.Path)
			}
		}
	}
	for path, found := range seen {
		if !found {
			t.Errorf("no recorded request for path %q", path)
		}
	}
}

// ---------------------------------------------------------------------------
// Cipher, folder, and attachment endpoint integration
// ---------------------------------------------------------------------------

func TestVaultCipherFolderAttachmentEndpoints(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	client := &http.Client{}
	bearer := "Bearer test-access-token"
	base := s.IdentityURL()

	// 1. Create cipher (POST /ciphers)
	req, err := http.NewRequest("POST", base+"/ciphers", strings.NewReader(`{"type":1,"name":"2.test-name"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", bearer)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST /ciphers: expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 2. Update cipher (PUT /ciphers/{id})
	req, err = http.NewRequest("PUT", base+"/ciphers/cipher-id-1", strings.NewReader(`{"type":1,"name":"2.updated-name"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", bearer)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PUT /ciphers/{id}: expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 3. Restore cipher (PUT /ciphers/{id}/restore)
	req, err = http.NewRequest("PUT", base+"/ciphers/cipher-id-1/restore", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", bearer)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PUT /ciphers/{id}/restore: expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 4. Bulk delete ciphers (POST /ciphers/delete)
	req, err = http.NewRequest("POST", base+"/ciphers/delete", strings.NewReader(`{"ids":["cipher-id-1"]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", bearer)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST /ciphers/delete: expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 5. Delete individual cipher (DELETE /ciphers/{id})
	req, err = http.NewRequest("DELETE", base+"/ciphers/cipher-id-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", bearer)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DELETE /ciphers/{id}: expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 6. List folders (GET /folders)
	req, err = http.NewRequest("GET", base+"/folders", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", bearer)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /folders: expected 200, got %d", resp.StatusCode)
	}
	// Verify it's a JSON array.
	var folders []any
	if err := json.NewDecoder(resp.Body).Decode(&folders); err != nil {
		t.Errorf("GET /folders: expected JSON array, got error: %v", err)
	}
	_ = resp.Body.Close()

	// 7. Create folder (POST /folders)
	req, err = http.NewRequest("POST", base+"/folders", strings.NewReader(`{"name":"2.test-folder"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", bearer)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST /folders: expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 8. Update folder (PUT /folders/{id})
	req, err = http.NewRequest("PUT", base+"/folders/folder-id-1", strings.NewReader(`{"name":"2.updated-folder"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", bearer)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PUT /folders/{id}: expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 9. Delete folder (DELETE /folders/{id})
	req, err = http.NewRequest("DELETE", base+"/folders/folder-id-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", bearer)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DELETE /folders/{id}: expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 10. Create attachment (POST /ciphers/{id}/attachment/v2)
	req, err = http.NewRequest("POST", base+"/ciphers/cipher-id-1/attachment/v2", strings.NewReader(`{"fileName":"test.txt","fileSize":128}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", bearer)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST /ciphers/{id}/attachment/v2: expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 11. Delete attachment (DELETE /ciphers/{id}/attachment/{attachmentId})
	req, err = http.NewRequest("DELETE", base+"/ciphers/cipher-id-1/attachment/att-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", bearer)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DELETE /ciphers/{id}/attachment/{id}: expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Verify all expected requests were recorded.
	if err := s.Recorder().AssertRequest("POST", "/ciphers"); err != nil {
		t.Error(err)
	}
	if err := s.Recorder().AssertRequest("PUT", "/ciphers/cipher-id-1"); err != nil {
		t.Error(err)
	}
	if err := s.Recorder().AssertRequest("PUT", "/ciphers/cipher-id-1/restore"); err != nil {
		t.Error(err)
	}
	if err := s.Recorder().AssertRequest("POST", "/ciphers/delete"); err != nil {
		t.Error(err)
	}
	if err := s.Recorder().AssertRequest("DELETE", "/ciphers/cipher-id-1"); err != nil {
		t.Error(err)
	}
	if err := s.Recorder().AssertRequest("GET", "/folders"); err != nil {
		t.Error(err)
	}
	if err := s.Recorder().AssertRequest("POST", "/folders"); err != nil {
		t.Error(err)
	}
	if err := s.Recorder().AssertRequest("PUT", "/folders/folder-id-1"); err != nil {
		t.Error(err)
	}
	if err := s.Recorder().AssertRequest("DELETE", "/folders/folder-id-1"); err != nil {
		t.Error(err)
	}
	if err := s.Recorder().AssertRequest("POST", "/ciphers/cipher-id-1/attachment/v2"); err != nil {
		t.Error(err)
	}
	if err := s.Recorder().AssertRequest("DELETE", "/ciphers/cipher-id-1/attachment/att-1"); err != nil {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// Direct attachment upload content endpoint
// ---------------------------------------------------------------------------

func TestVaultDirectAttachmentUploadContentEndpoint(t *testing.T) {
	s := NewServer(t, NewScenario(WithDirectAttachmentUpload()))
	defer s.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	base := s.IdentityURL()
	bearer := "Bearer test-token"

	// POST multipart data to /ciphers/c1/attachment/a1
	var buf bytes.Buffer
	mp := multipart.NewWriter(&buf)
	dataField, err := mp.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = dataField.Write([]byte("SECRET_ATTACHMENT_BYTES"))
	if err := mp.Close(); err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", base+"/ciphers/c1/attachment/a1", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mp.FormDataContentType())
	req.Header.Set("Authorization", bearer)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Accept 200 or 204.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 200 or 204, got %d", resp.StatusCode)
	}

	// Verify recorder has no SECRET_ATTACHMENT_BYTES.
	reqs := s.Recorder().Requests()
	for _, recReq := range reqs {
		for _, f := range recReq.KnownFields {
			if strings.Contains(f, "SECRET_ATTACHMENT_BYTES") {
				t.Errorf("recorder leaks SECRET_ATTACHMENT_BYTES in KnownFields: %q", f)
			}
		}
	}
	if err := s.Recorder().AssertNoRawBodies(); err != nil {
		t.Errorf("AssertNoRawBodies failed: %v", err)
	}
	if err := s.Recorder().AssertRequest("POST", "/ciphers/c1/attachment/a1"); err != nil {
		t.Errorf("expected recorded request: %v", err)
	}
}

// ---------------------------------------------------------------------------
// External attachment upload is self-contained (no external networking)
// ---------------------------------------------------------------------------

func TestVaultExternalUploadIsSelfContained(t *testing.T) {
	s := NewServer(t, NewScenario(WithExternalAttachmentUpload()))
	defer s.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	base := s.IdentityURL()
	bearer := "Bearer test-token"

	// Step 1: Create attachment (POST /ciphers/c1/attachment/v2)
	createReq, err := http.NewRequest("POST", base+"/ciphers/c1/attachment/v2", strings.NewReader(`{"fileName":"test.bin","fileSize":32}`))
	if err != nil {
		t.Fatal(err)
	}
	createReq.Header.Set("Content-Type", "application/json; charset=utf-8")
	createReq.Header.Set("Authorization", bearer)

	createResp, err := client.Do(createReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = createResp.Body.Close() }()

	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("create attachment: expected 200, got %d", createResp.StatusCode)
	}

	// Step 2: Parse the upload URL from the response.
	var createBody struct {
		AttachmentID string `json:"AttachmentId"`
		URL          string `json:"Url"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&createBody); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	if createBody.URL == "" {
		t.Fatal("upload URL is empty")
	}

	// Step 3: Assert the upload URL host matches the test server host.
	parsedURL, err := url.Parse(createBody.URL)
	if err != nil {
		t.Fatalf("parse upload URL: %v", err)
	}
	if parsedURL.Host != s.srv.Listener.Addr().String() {
		t.Errorf("upload URL host %q does not match server host %q", parsedURL.Host, s.srv.Listener.Addr().String())
	}

	// Step 4: PUT sentinel bytes to the upload URL successfully.
	sentinel := []byte("SENTINEL_UPLOAD_BYTES")
	uploadReq, err := http.NewRequest("PUT", createBody.URL, bytes.NewReader(sentinel))
	if err != nil {
		t.Fatal(err)
	}
	uploadResp, err := client.Do(uploadReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = uploadResp.Body.Close() }()
	if uploadResp.StatusCode != http.StatusOK {
		t.Errorf("upload: expected 200, got %d", uploadResp.StatusCode)
	}

	// Step 5: Verify recorder does not leak the sentinel.
	reqs := s.Recorder().Requests()
	for _, recReq := range reqs {
		for _, f := range recReq.KnownFields {
			if strings.Contains(f, "SENTINEL_UPLOAD_BYTES") {
				t.Errorf("recorder leaks SENTINEL_UPLOAD_BYTES: %q", f)
			}
		}
	}
	if err := s.Recorder().AssertNoRawBodies(); err != nil {
		t.Errorf("AssertNoRawBodies failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Accounts revision date endpoint
// ---------------------------------------------------------------------------

func TestVaultAccountsRevisionDateEndpoint(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	base := s.IdentityURL()
	bearer := "Bearer test-token"

	req, err := http.NewRequest("GET", base+"/accounts/revision-date", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", bearer)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Verify response is valid JSON (a number).
	var revisionDate json.Number
	if err := json.NewDecoder(resp.Body).Decode(&revisionDate); err != nil {
		t.Errorf("response is not valid JSON number: %v", err)
	}

	// Verify recorder.
	if err := s.Recorder().AssertRequest("GET", "/accounts/revision-date"); err != nil {
		t.Errorf("assert request: %v", err)
	}

	// Also verify /sync/revision-date still works for backward compatibility.
	req2, err := http.NewRequest("GET", base+"/sync/revision-date", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Authorization", bearer)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("/sync/revision-date: expected 200, got %d", resp2.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Recorder safety: no secrets stored in vault endpoints
// ---------------------------------------------------------------------------

func TestVaultRecorderDoesNotStoreSecrets(t *testing.T) {
	s := NewServer(t, NewScenario())
	defer s.Close()

	client := &http.Client{}

	// Send requests with sentinel values in body and header.
	tests := []struct {
		method  string
		path    string
		body    string
		headers map[string]string
	}{
		{
			method: "POST",
			path:   "/ciphers",
			body:   `{"password":"SECRET_PASSWORD","name":"test"}`,
			headers: map[string]string{
				"Content-Type":  "application/json; charset=utf-8",
				"Authorization": "Bearer SECRET_TOKEN_VALUE",
			},
		},
		{
			method: "POST",
			path:   "/folders",
			body:   `{"name":"SECRET_PASSWORD"}`,
			headers: map[string]string{
				"Content-Type":  "application/json; charset=utf-8",
				"Authorization": "Bearer any-token",
			},
		},
		{
			method: "POST",
			path:   "/ciphers/cipher-id-1/attachment/v2",
			body:   `{"fileName":"SECRET_ATTACHMENT_BYTES"}`,
			headers: map[string]string{
				"Content-Type":  "application/json; charset=utf-8",
				"Authorization": "Bearer any-token",
			},
		},
	}

	for _, tt := range tests {
		req, err := http.NewRequest(tt.method, s.IdentityURL()+tt.path, strings.NewReader(tt.body))
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range tt.headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}

	// Verify that KnownFields contain only field names, not sentinel values.
	reqs := s.Recorder().Requests()
	for _, recReq := range reqs {
		for _, field := range recReq.KnownFields {
			if strings.Contains(field, "SECRET_PASSWORD") ||
				strings.Contains(field, "SECRET_AUTH_HASH") ||
				strings.Contains(field, "SECRET_REFRESH_TOKEN") ||
				strings.Contains(field, "SECRET_ATTACHMENT_BYTES") {
				t.Errorf("KnownFields leaks secret value: %q", field)
			}
		}
	}

	// AssertNoRawBodies must pass.
	if err := s.Recorder().AssertNoRawBodies(); err != nil {
		t.Fatalf("AssertNoRawBodies failed: %v", err)
	}

	// Error messages from assertions must not contain sentinel values.
	if err := s.Recorder().AssertRequest("GET", "/nonexistent"); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "SECRET_PASSWORD") ||
			strings.Contains(msg, "SECRET_AUTH_HASH") ||
			strings.Contains(msg, "SECRET_REFRESH_TOKEN") ||
			strings.Contains(msg, "SECRET_ATTACHMENT_BYTES") ||
			strings.Contains(msg, "SECRET_TOKEN_VALUE") {
			t.Errorf("assertion error leaks secret: %s", msg)
		}
	}
}

// ---------------------------------------------------------------------------
// Recorder returns independent copies
// ---------------------------------------------------------------------------

func TestRecorderRequestsReturnsIndependentCopy(t *testing.T) {
	rec := NewRecorder()
	rec.Record(SafeRecordedRequest{
		Method:      "POST",
		Path:        "/test",
		KnownFields: []string{"field1", "field2"},
	})

	// Get the copy and mutate it.
	copy1 := rec.Requests()
	copy1[0].KnownFields[0] = "MUTATED"

	// Get another copy — the original must be unchanged.
	copy2 := rec.Requests()
	if len(copy2) != 1 {
		t.Fatalf("expected 1 request, got %d", len(copy2))
	}
	if copy2[0].KnownFields[0] != "field1" {
		t.Errorf("internal KnownFields was mutated: got %q, want %q", copy2[0].KnownFields[0], "field1")
	}
	if copy2[0].KnownFields[1] != "field2" {
		t.Errorf("internal KnownFields was mutated: got %q, want %q", copy2[0].KnownFields[1], "field2")
	}
}
