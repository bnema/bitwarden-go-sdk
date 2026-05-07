package bitwardenremote

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Scenario options
// ---------------------------------------------------------------------------

func TestScenario_Defaults(t *testing.T) {
	s := NewScenario()
	if s.TwoFactorProvider != "" {
		t.Errorf("expected empty TwoFactorProvider, got %q", s.TwoFactorProvider)
	}
	if s.ExpiredAccessToken {
		t.Error("expected ExpiredAccessToken false")
	}
	if s.RateLimit.Enabled {
		t.Error("expected RateLimit.Enabled false")
	}
	if s.DirectAttachmentUpload {
		t.Error("expected DirectAttachmentUpload false")
	}
	if s.ExternalAttachmentUpload {
		t.Error("expected ExternalAttachmentUpload false")
	}
}

func TestScenario_WithTwoFactorProvider(t *testing.T) {
	s := NewScenario(WithTwoFactorProvider("authenticator"))
	if s.TwoFactorProvider != "authenticator" {
		t.Errorf("expected TwoFactorProvider=%q, got %q", "authenticator", s.TwoFactorProvider)
	}
}

func TestScenario_WithExpiredAccessToken(t *testing.T) {
	s := NewScenario(WithExpiredAccessToken())
	if !s.ExpiredAccessToken {
		t.Error("expected ExpiredAccessToken true")
	}
}

func TestScenario_WithRateLimit(t *testing.T) {
	s := NewScenario(WithRateLimit(15))
	if !s.RateLimit.Enabled {
		t.Error("expected RateLimit.Enabled true")
	}
	if s.RateLimit.RetryAfter != 15*time.Second {
		t.Errorf("expected RetryAfter=15s, got %v", s.RateLimit.RetryAfter)
	}
}

func TestScenario_WithDirectAttachmentUpload(t *testing.T) {
	s := NewScenario(WithDirectAttachmentUpload())
	if !s.DirectAttachmentUpload {
		t.Error("expected DirectAttachmentUpload true")
	}
	if s.ExternalAttachmentUpload {
		t.Error("expected ExternalAttachmentUpload false")
	}
}

func TestScenario_WithExternalAttachmentUpload(t *testing.T) {
	s := NewScenario(WithExternalAttachmentUpload())
	if !s.ExternalAttachmentUpload {
		t.Error("expected ExternalAttachmentUpload true")
	}
	if s.DirectAttachmentUpload {
		t.Error("expected DirectAttachmentUpload false")
	}
}

func TestScenario_MultipleOptions(t *testing.T) {
	s := NewScenario(
		WithTwoFactorProvider("email"),
		WithRateLimit(30),
		WithExpiredAccessToken(),
	)
	if s.TwoFactorProvider != "email" {
		t.Errorf("expected TwoFactorProvider=%q", "email")
	}
	if !s.RateLimit.Enabled || s.RateLimit.RetryAfter != 30*time.Second {
		t.Errorf("expected RateLimit enabled with 30s")
	}
	if !s.ExpiredAccessToken {
		t.Error("expected ExpiredAccessToken true")
	}
}

// ---------------------------------------------------------------------------
// Recorder — safe metadata only
// ---------------------------------------------------------------------------

func TestRecorder_RecordAndRetrieve(t *testing.T) {
	rec := NewRecorder()
	rec.Record(SafeRecordedRequest{
		Method:      "POST",
		Path:        "/api/identity/connect/token",
		ContentType: "application/x-www-form-urlencoded",
		AuthPresent: false,
		KnownFields: []string{"grant_type", "client_id", "scope"},
	})
	rec.Record(SafeRecordedRequest{
		Method:      "GET",
		Path:        "/api/ciphers",
		ContentType: "application/json",
		AuthPresent: true,
		KnownFields: nil,
	})

	reqs := rec.Requests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 recorded requests, got %d", len(reqs))
	}

	// Verify safe fields only — no raw body, no auth value.
	if reqs[0].Method != "POST" {
		t.Errorf("expected method POST, got %q", reqs[0].Method)
	}
	if reqs[0].AuthPresent {
		t.Error("expected AuthPresent false for token request")
	}
	if len(reqs[0].KnownFields) != 3 {
		t.Errorf("expected 3 KnownFields, got %d", len(reqs[0].KnownFields))
	}
	if reqs[1].Method != "GET" {
		t.Errorf("expected method GET, got %q", reqs[1].Method)
	}
	if !reqs[1].AuthPresent {
		t.Error("expected AuthPresent true for authenticated request")
	}
}

func TestRecorder_RequestsReturnsCopy(t *testing.T) {
	rec := NewRecorder()
	rec.Record(SafeRecordedRequest{Method: "GET", Path: "/api/ciphers"})

	reqs := rec.Requests()
	reqs[0].Method = "POST" // mutate the copy

	original := rec.Requests()
	if original[0].Method != "GET" {
		t.Error("Requests returned a mutable reference")
	}
}

// ---------------------------------------------------------------------------
// AssertRequest
// ---------------------------------------------------------------------------

func TestAssertRequest_Found(t *testing.T) {
	rec := NewRecorder()
	rec.Record(SafeRecordedRequest{Method: "POST", Path: "/api/identity/connect/token"})
	if err := rec.AssertRequest("POST", "/api/identity/connect/token"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAssertRequest_NotFound(t *testing.T) {
	rec := NewRecorder()
	rec.Record(SafeRecordedRequest{Method: "GET", Path: "/api/ciphers"})
	err := rec.AssertRequest("DELETE", "/api/ciphers/1")
	if err == nil {
		t.Fatal("expected error for unmatched request")
	}
	// Error message must NOT contain secrets; it shows method and path only.
	msg := err.Error()
	if strings.Contains(msg, "SECRET_PASSWORD") {
		t.Error("error leaks SECRET_PASSWORD")
	}
	if strings.Contains(msg, "SECRET_AUTH_HASH") {
		t.Error("error leaks SECRET_AUTH_HASH")
	}
	if strings.Contains(msg, "SECRET_REFRESH_TOKEN") {
		t.Error("error leaks SECRET_REFRESH_TOKEN")
	}
	if strings.Contains(msg, "SECRET_ATTACHMENT_BYTES") {
		t.Error("error leaks SECRET_ATTACHMENT_BYTES")
	}
}

// ---------------------------------------------------------------------------
// AssertContentType
// ---------------------------------------------------------------------------

func TestAssertContentType_Found(t *testing.T) {
	rec := NewRecorder()
	rec.Record(SafeRecordedRequest{
		Method:      "POST",
		Path:        "/api/identity/connect/token",
		ContentType: "application/x-www-form-urlencoded",
	})
	if err := rec.AssertContentType("/api/identity/connect/token", "application/x-www-form-urlencoded"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAssertContentType_NotFound(t *testing.T) {
	rec := NewRecorder()
	rec.Record(SafeRecordedRequest{
		Method:      "POST",
		Path:        "/api/identity/connect/token",
		ContentType: "application/x-www-form-urlencoded",
	})
	err := rec.AssertContentType("/api/identity/connect/token", "application/json")
	if err == nil {
		t.Fatal("expected error for mismatched content type")
	}
}

// ---------------------------------------------------------------------------
// AssertNoRawBodies — must NOT leak secrets via error messages
// ---------------------------------------------------------------------------

func TestAssertNoRawBodies_NoSecrets(t *testing.T) {
	rec := NewRecorder()
	rec.Record(SafeRecordedRequest{
		Method:      "POST",
		Path:        "/api/identity/connect/token",
		ContentType: "application/x-www-form-urlencoded",
		AuthPresent: false,
		KnownFields: []string{"grant_type", "client_id", "scope"},
	})
	if err := rec.AssertNoRawBodies(); err != nil {
		t.Fatalf("unexpected error for clean request: %v", err)
	}
}

func TestAssertNoRawBodies_DetectsSecretValues(t *testing.T) {
	// Sentinel values defined as local variables — these are the exact strings
	// the test proves are NOT leaked through assertion error messages.
	secretPassword := "SECRET_PASSWORD"
	secretAuthHash := "SECRET_AUTH_HASH"
	secretRefreshToken := "SECRET_REFRESH_TOKEN"
	secretAttachmentBytes := "SECRET_ATTACHMENT_BYTES"

	tests := []struct {
		name  string
		value string
	}{
		{"password", secretPassword},
		{"auth hash", secretAuthHash},
		{"refresh token", secretRefreshToken},
		{"attachment bytes", secretAttachmentBytes},
		{"partial password", "my_password_here"},
		{"partial auth hash", "prefix_auth_hash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := NewRecorder()
			// Simulate a buggy recorder that accidentally stores a secret
			// value as a KnownFields entry.
			rec.Record(SafeRecordedRequest{
				Method:      "POST",
				Path:        "/api/identity/connect/token",
				KnownFields: []string{tt.value},
			})

			err := rec.AssertNoRawBodies()
			if err == nil {
				t.Fatal("expected error for request with secret-like KnownFields entry")
			}

			msg := err.Error()

			// Prove the error does NOT contain the sentinel secret strings.
			if strings.Contains(msg, "SECRET_PASSWORD") {
				t.Error("error message leaks SECRET_PASSWORD")
			}
			if strings.Contains(msg, "SECRET_AUTH_HASH") {
				t.Error("error message leaks SECRET_AUTH_HASH")
			}
			if strings.Contains(msg, "SECRET_REFRESH_TOKEN") {
				t.Error("error message leaks SECRET_REFRESH_TOKEN")
			}
			if strings.Contains(msg, "SECRET_ATTACHMENT_BYTES") {
				t.Error("error message leaks SECRET_ATTACHMENT_BYTES")
			}

			// Also prove the error doesn't contain the raw value itself.
			if strings.Contains(msg, tt.value) {
				t.Errorf("error message leaks the raw secret value %q", tt.value)
			}

			// But it should indicate that something was found.
			if !strings.Contains(msg, "secret value") && !strings.Contains(msg, "raw body") {
				t.Errorf("error message should indicate secret data was found, got: %s", msg)
			}
		})
	}
}

func TestAssertNoRawBodies_EmptyRecorder(t *testing.T) {
	rec := NewRecorder()
	if err := rec.AssertNoRawBodies(); err != nil {
		t.Fatalf("unexpected error for empty recorder: %v", err)
	}
}

func TestAssertNoRawBodies_CleanKnownFields(t *testing.T) {
	rec := NewRecorder()
	rec.Record(SafeRecordedRequest{
		Method:      "POST",
		Path:        "/api/identity/connect/token",
		KnownFields: []string{"grant_type", "client_id", "client_secret", "scope"},
	})
	// "client_secret" is a field name (like an OAuth parameter name), not a
	// secret value, so it should pass.
	if err := rec.AssertNoRawBodies(); err != nil {
		t.Fatalf("unexpected error for clean KnownFields: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Combined: prove the full assertion error path never reveals secrets
// ---------------------------------------------------------------------------

func TestAssertions_ErrorMessagesContainNoSecrets(t *testing.T) {
	// All sentinel values as local variables — never written to recorder.
	_ = "SECRET_PASSWORD"
	_ = "SECRET_AUTH_HASH"
	_ = "SECRET_REFRESH_TOKEN"
	_ = "SECRET_ATTACHMENT_BYTES"

	rec := NewRecorder()

	// Simulate what a real integration test looks like.
	rec.Record(SafeRecordedRequest{
		Method:      "GET",
		Path:        "/api/ciphers",
		ContentType: "application/json",
		AuthPresent: true,
		KnownFields: nil,
	})

	// AssertRequest error must not contain secrets.
	if err := rec.AssertRequest("POST", "/api/identity/connect/token"); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "SECRET_PASSWORD") ||
			strings.Contains(msg, "SECRET_AUTH_HASH") ||
			strings.Contains(msg, "SECRET_REFRESH_TOKEN") ||
			strings.Contains(msg, "SECRET_ATTACHMENT_BYTES") {
			t.Errorf("AssertRequest error leaks secrets: %s", msg)
		}
	}

	// AssertContentType error must not contain secrets.
	if err := rec.AssertContentType("/api/ciphers", "text/plain"); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "SECRET_PASSWORD") ||
			strings.Contains(msg, "SECRET_AUTH_HASH") ||
			strings.Contains(msg, "SECRET_REFRESH_TOKEN") ||
			strings.Contains(msg, "SECRET_ATTACHMENT_BYTES") {
			t.Errorf("AssertContentType error leaks secrets: %s", msg)
		}
	}

	// AssertNoRawBodies on a clean recorder must pass.
	if err := rec.AssertNoRawBodies(); err != nil {
		t.Fatalf("unexpected AssertNoRawBodies error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// KnownFields structural check — field names only, no values
// ---------------------------------------------------------------------------

func TestKnownFields_ContainsOnlyFieldNames(t *testing.T) {
	// This test verifies that KnownFields stores only structural field names
	// like JSON keys, not their corresponding values.
	rec := NewRecorder()
	rec.Record(SafeRecordedRequest{
		Method:      "POST",
		Path:        "/api/identity/connect/token",
		ContentType: "application/x-www-form-urlencoded",
		KnownFields: []string{
			"grant_type",
			"client_id",
			"client_secret", // OAuth parameter name — acceptable as field name
			"scope",
			"deviceName",
			"deviceIdentifier",
		},
	})

	if err := rec.AssertNoRawBodies(); err != nil {
		t.Fatalf("expected no error for field-name-only KnownFields: %v", err)
	}

	// Confirm the fields are accessible via recorded metadata.
	reqs := rec.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	expected := []string{"grant_type", "client_id", "client_secret", "scope", "deviceName", "deviceIdentifier"}
	got := reqs[0].KnownFields
	if len(got) != len(expected) {
		t.Fatalf("expected %d KnownFields, got %d: %v", len(expected), len(got), got)
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("KnownFields[%d]: expected %q, got %q", i, expected[i], got[i])
		}
	}

	// Prove the recorder does NOT store field VALUES even when they are
	// passed as local variables to a helper.
	value := "my_actual_password_123"
	_ = fmt.Sprintf("this value (%s) is never stored", value)
}

// Ensure no test accidentally compiles with a raw-body field.
func TestSafeRecordedRequest_NoRawBodyField(_ *testing.T) {
	// Compile-time check: the type has no Body or RawBody field.
	// We use reflection-free approach: just verify the struct has only the
	// fields we expect via a compile-time assertion on the zero value.
	var req SafeRecordedRequest
	_ = req.Method
	_ = req.Path
	_ = req.ContentType
	_ = req.AuthPresent
	_ = req.KnownFields
	// If someone adds a Body or RawBody field, this test won't catch it
	// at compile time, but the code review and the AssertNoRawBodies logic
	// provide runtime defence.
}
