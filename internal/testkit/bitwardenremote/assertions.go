package bitwardenremote

import (
	"fmt"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Safe recorded request — no raw bodies, no secrets, no auth values.
// ---------------------------------------------------------------------------

// SafeRecordedRequest stores only metadata about a captured HTTP request.
// It MUST NOT store the raw body, the Authorization header value, tokens,
// passwords, auth hashes, refresh tokens, attachment content, or any
// arbitrary header values.
type SafeRecordedRequest struct {
	// Method is the HTTP method (GET, POST, PUT, DELETE, …).
	Method string

	// Path is the request URL path, e.g. "/api/identity/connect/token".
	Path string

	// ContentType is the value of the Content-Type header, if present.
	ContentType string

	// AuthPresent is true when the request carried an Authorization header.
	AuthPresent bool

	// KnownFields holds the structural JSON/ form field names parsed from
	// the request body — never their values.
	KnownFields []string
}

// Recorder holds a sequence of safe recorded requests. It is the
// test-harness-side state against which assertions are run.
type Recorder struct {
	mu       sync.Mutex
	requests []SafeRecordedRequest
}

// NewRecorder returns an empty Recorder.
func NewRecorder() *Recorder {
	return &Recorder{}
}

// Record appends a safe recorded request. It is the caller's responsibility
// to ensure no sensitive values leak into the SafeRecordedRequest fields.
func (r *Recorder) Record(req SafeRecordedRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
}

// Requests returns a deep-enough copy of the recorded requests so callers
// cannot mutate internal state.
func (r *Recorder) Requests() []SafeRecordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SafeRecordedRequest, len(r.requests))
	for i, req := range r.requests {
		out[i] = req
		if req.KnownFields != nil {
			out[i].KnownFields = make([]string, len(req.KnownFields))
			copy(out[i].KnownFields, req.KnownFields)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

// AssertNoRawBodies verifies that no recorded request contains a raw body,
// raw header values for sensitive keys, or any stored secret data. Since the
// SafeRecordedRequest type intentionally excludes those fields, this check
// is structural: it ensures the KnownFields slice contains only field names,
// never values that look like secrets.
//
// The returned error deliberately omits the offending values to avoid leaking
// secrets through assertion error messages.
func (r *Recorder) AssertNoRawBodies() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var count int
	for i, req := range r.requests {
		for j, f := range req.KnownFields {
			if looksLikeSecretValue(f) {
				count++
				_ = i // used for future diagnostic expansion
				_ = j
			}
		}
	}
	if count > 0 {
		return fmt.Errorf("%d KnownFields entr%s look like secret value%s; raw body/secret data found",
			count,
			ternary(count == 1, "y", "ies"),
			ternary(count == 1, "", "s"),
		)
	}
	return nil
}

// AssertRequest checks that at least one recorded request matches the given
// method and path.
func (r *Recorder) AssertRequest(method, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, req := range r.requests {
		if strings.EqualFold(req.Method, method) && req.Path == path {
			return nil
		}
	}
	return fmt.Errorf("no recorded request with method=%q path=%q", method, path)
}

// AssertContentType checks that at least one recorded request whose path
// matches the given path has the given Content-Type.
func (r *Recorder) AssertContentType(path, want string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, req := range r.requests {
		if req.Path == path && req.ContentType == want {
			return nil
		}
	}
	return fmt.Errorf("no recorded request with path=%q and Content-Type=%q", path, want)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// looksLikeSecretValue is a best-effort heuristic to detect accidental
// secret storage inside KnownFields. It catches the sentinel values the
// tests use while allowing legitimate structural field names like
// "password", "refresh_token" (which are OAuth form keys).
func looksLikeSecretValue(s string) bool {
	lower := strings.ToLower(s)

	// Catch sentinel test values that exactly match or contain the prefix.
	if strings.Contains(lower, "secret_password") ||
		strings.Contains(lower, "secret_auth_hash") ||
		strings.Contains(lower, "secret_refresh_token") ||
		strings.Contains(lower, "secret_attachment_bytes") {
		return true
	}

	// For generic substrings, require the string to be longer than the
	// keyword itself to avoid flagging structural field names like
	// "password" or "refresh_token" as secret values.
	if len(lower) > len("password") && strings.Contains(lower, "password") {
		return true
	}
	if len(lower) > len("auth_hash") && strings.Contains(lower, "auth_hash") {
		return true
	}
	if len(lower) > len("refresh_token") && strings.Contains(lower, "refresh_token") {
		return true
	}
	if len(lower) > len("attachment_bytes") && strings.Contains(lower, "attachment_bytes") {
		return true
	}

	return false
}

// ternary is a generic inline conditional for use in expressions.
func ternary[T any](cond bool, t, f T) T {
	if cond {
		return t
	}
	return f
}
