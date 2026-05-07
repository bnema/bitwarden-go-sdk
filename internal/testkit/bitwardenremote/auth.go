package bitwardenremote

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// ---------------------------------------------------------------------------
// Prelogin handler
// ---------------------------------------------------------------------------

func (s *Server) preloginHandler(w http.ResponseWriter, r *http.Request) {
	// Method check.
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Content-Type must be exactly "application/json; charset=utf-8".
	if r.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	// Parse JSON body — record keys only, never values.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Record field names only.
	knownFields := make([]string, 0, len(raw))
	for k := range raw {
		knownFields = append(knownFields, k)
	}

	s.recorder.Record(SafeRecordedRequest{
		Method:      r.Method,
		Path:        r.URL.Path,
		ContentType: r.Header.Get("Content-Type"),
		AuthPresent: r.Header.Get("Authorization") != "",
		KnownFields: knownFields,
	})

	// Return the default PBKDF2 prelogin fixture.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(preloginResponsePbkdf2))
}

// ---------------------------------------------------------------------------
// Token handler
// ---------------------------------------------------------------------------

func (s *Server) tokenHandler(w http.ResponseWriter, r *http.Request) {
	// Method check.
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Content-Type must be exactly "application/x-www-form-urlencoded; charset=utf-8".
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded; charset=utf-8" {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	// Read body for parsing — we must not store raw values.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	formValues, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Record field names only, never values.
	knownFields := make([]string, 0, len(formValues))
	for k := range formValues {
		knownFields = append(knownFields, k)
	}

	s.recorder.Record(SafeRecordedRequest{
		Method:      r.Method,
		Path:        r.URL.Path,
		ContentType: r.Header.Get("Content-Type"),
		AuthPresent: r.Header.Get("Authorization") != "",
		KnownFields: knownFields,
	})

	grantType := formValues.Get("grant_type")

	// Rate limit check — must happen before any grant-type logic.
	if s.scenario.RateLimit.Enabled {
		retryAfter := max(int(s.scenario.RateLimit.RetryAfter.Seconds()), 1)
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate_limited","error_description":"Rate limit exceeded."}`))
		return
	}

	switch grantType {
	case "password":
		s.handlePasswordGrant(w, r, formValues)
	case "refresh_token":
		s.handleRefreshGrant(w, formValues)
	default:
		s.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Unsupported grant type.")
	}
}

// handlePasswordGrant processes a password-based token request.
func (s *Server) handlePasswordGrant(w http.ResponseWriter, _ *http.Request, formValues url.Values) {
	// Validate required fields for password grant.
	missing := make([]string, 0)
	if formValues.Get("username") == "" {
		missing = append(missing, "username")
	}
	if formValues.Get("password") == "" {
		missing = append(missing, "password")
	}
	if formValues.Get("scope") == "" {
		missing = append(missing, "scope")
	}
	if formValues.Get("client_id") == "" {
		missing = append(missing, "client_id")
	}
	if len(missing) > 0 {
		s.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Missing required grant fields.")
		return
	}

	// If 2FA is required by the scenario AND the form does not include a
	// twoFactorToken field, return a 2FA challenge.
	needsTwoFactor := s.scenario.TwoFactorProvider != ""
	hasTwoFactor := formValues.Get("twoFactorToken") != "" && formValues.Get("twoFactorProvider") != ""

	if needsTwoFactor {
		// If 2FA is required, also require twoFactorToken and twoFactorProvider.
		if !hasTwoFactor {
			missing2FA := make([]string, 0)
			if formValues.Get("twoFactorToken") == "" {
				missing2FA = append(missing2FA, "twoFactorToken")
			}
			if formValues.Get("twoFactorProvider") == "" {
				missing2FA = append(missing2FA, "twoFactorProvider")
			}
			_ = missing2FA // not included in error
			s.writeTwoFactorChallenge(w)
			return
		}
	}

	// Success: return token_success_response fixture.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(tokenSuccessResponse))
}

// handleRefreshGrant processes a refresh_token request.
func (s *Server) handleRefreshGrant(w http.ResponseWriter, formValues url.Values) {
	// Validate required fields for refresh grant.
	if formValues.Get("refresh_token") == "" || formValues.Get("client_id") == "" {
		s.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Missing required grant fields.")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(tokenRefreshResponse))
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

// writeTwoFactorChallenge writes a JSON error response indicating that
// two-factor authentication is required.
func (s *Server) writeTwoFactorChallenge(w http.ResponseWriter) {
	providerID := providerNameToNumeric(s.scenario.TwoFactorProvider)

	tfp := map[string]any{
		providerID: nil,
	}
	tfp2 := map[string]any{
		providerID: map[string]any{},
	}

	resp := map[string]any{
		"error":               "invalid_grant",
		"error_description":   "Two factor required.",
		"TwoFactorProviders":  tfp,
		"TwoFactorProviders2": tfp2,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(resp)
}

// writeTokenError writes a JSON error response for the token endpoint.
func (s *Server) writeTokenError(w http.ResponseWriter, status int, errCode, errDesc string) {
	body := map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ---------------------------------------------------------------------------
// Provider mapping
// ---------------------------------------------------------------------------

// providerNameToNumeric maps a TwoFactorProvider string name to its numeric
// form value as used by the Bitwarden API.
func providerNameToNumeric(provider string) string {
	switch provider {
	case "authenticator":
		return "0"
	case "email":
		return "1"
	case "duo":
		return "2"
	case "yubikey":
		return "3"
	default:
		return "0"
	}
}
