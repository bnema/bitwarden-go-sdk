package bitwardenremote

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

// requireAuth checks that the request carries an Authorization header and
// that the token has not expired according to the scenario. If the check
// fails it writes an error response directly and returns false.
func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"Authorization header required."}`))
		return false
	}

	if s.scenario.ExpiredAccessToken {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"expired_access_token","error_description":"Access token has expired."}`))
		return false
	}

	return true
}

// ---------------------------------------------------------------------------
// Safe request body parsing helpers
// ---------------------------------------------------------------------------

// recordJSONBody reads the request body as JSON, records the key names only,
// and discards the body. It returns true on success.
func (s *Server) recordJSONBody(r *http.Request) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}

	knownFields := make([]string, 0, len(raw))
	for k := range raw {
		knownFields = append(knownFields, k)
	}

	var queryKeys []string
	if len(r.URL.Query()) > 0 {
		queryKeys = make([]string, 0, len(r.URL.Query()))
		for k := range r.URL.Query() {
			queryKeys = append(queryKeys, k)
		}
	}

	s.recorder.Record(SafeRecordedRequest{
		Method:      r.Method,
		Path:        r.URL.Path,
		QueryKeys:   queryKeys,
		ContentType: r.Header.Get("Content-Type"),
		AuthPresent: r.Header.Get("Authorization") != "",
		KnownFields: knownFields,
	})

	return true
}

// recordRequestMetadata records the request with minimal metadata and no
// body parsing (for GET/DELETE or endpoints where we do not parse the body).
func (s *Server) recordRequestMetadata(r *http.Request) {
	var queryKeys []string
	if len(r.URL.Query()) > 0 {
		queryKeys = make([]string, 0, len(r.URL.Query()))
		for k := range r.URL.Query() {
			queryKeys = append(queryKeys, k)
		}
	}
	s.recorder.Record(SafeRecordedRequest{
		Method:      r.Method,
		Path:        r.URL.Path,
		QueryKeys:   queryKeys,
		ContentType: r.Header.Get("Content-Type"),
		AuthPresent: r.Header.Get("Authorization") != "",
		KnownFields: nil,
	})
}

// recordAttachmentUpload records an attachment upload request without
// reading or storing the body — just method/path/content-type/auth-present
// with a KnownFields hint.
func (s *Server) recordAttachmentUpload(r *http.Request) {
	var queryKeys []string
	if len(r.URL.Query()) > 0 {
		queryKeys = make([]string, 0, len(r.URL.Query()))
		for k := range r.URL.Query() {
			queryKeys = append(queryKeys, k)
		}
	}
	s.recorder.Record(SafeRecordedRequest{
		Method:      r.Method,
		Path:        r.URL.Path,
		QueryKeys:   queryKeys,
		ContentType: r.Header.Get("Content-Type"),
		AuthPresent: r.Header.Get("Authorization") != "",
		KnownFields: []string{"attachment"},
	})
}

// writeJSON is a small helper to write a JSON response.
func (s *Server) writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// writeEmpty writes an empty response with the given status code.
func (s *Server) writeEmpty(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}

// ---------------------------------------------------------------------------
// GET /config
// ---------------------------------------------------------------------------

func (s *Server) configHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.recordRequestMetadata(r)
	s.writeJSON(w, http.StatusOK, configResponse)
}

// ---------------------------------------------------------------------------
// GET /accounts/profile
// ---------------------------------------------------------------------------

func (s *Server) accountProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordRequestMetadata(r)
	s.writeJSON(w, http.StatusOK, accountProfileResponse)
}

// ---------------------------------------------------------------------------
// GET /plans/subscription  (and /accounts/subscription)
// ---------------------------------------------------------------------------

func (s *Server) subscriptionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordRequestMetadata(r)
	s.writeJSON(w, http.StatusOK, subscriptionResponse)
}

// ---------------------------------------------------------------------------
// GET /sync
// ---------------------------------------------------------------------------

func (s *Server) syncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordRequestMetadata(r)
	s.writeJSON(w, http.StatusOK, syncResponsePersonal)
}

// ---------------------------------------------------------------------------
// GET /sync/revision-date
// ---------------------------------------------------------------------------

func (s *Server) syncRevisionDateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordRequestMetadata(r)
	s.writeJSON(w, http.StatusOK, revisionDateResponse)
}

// ---------------------------------------------------------------------------
// POST /ciphers
// ---------------------------------------------------------------------------

func (s *Server) createCipherHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordJSONBody(r)
	s.writeJSON(w, http.StatusOK, cipherResponseLogin)
}

// ---------------------------------------------------------------------------
// PUT /ciphers/{id}
// ---------------------------------------------------------------------------

func (s *Server) updateCipherHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordJSONBody(r)
	s.writeJSON(w, http.StatusOK, cipherResponseLogin)
}

// ---------------------------------------------------------------------------
// DELETE /ciphers/{id}
// ---------------------------------------------------------------------------

func (s *Server) deleteCipherHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordRequestMetadata(r)
	s.writeEmpty(w, http.StatusOK)
}

// ---------------------------------------------------------------------------
// PUT /ciphers/{id}/restore  and  POST /ciphers/{id}/restore
// ---------------------------------------------------------------------------

func (s *Server) restoreCipherHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordRequestMetadata(r)
	s.writeJSON(w, http.StatusOK, cipherRestoreResponse)
}

// ---------------------------------------------------------------------------
// POST /ciphers/delete — bulk delete
// ---------------------------------------------------------------------------

func (s *Server) bulkDeleteCiphersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordJSONBody(r)
	s.writeEmpty(w, http.StatusOK)
}

// ---------------------------------------------------------------------------
// GET /folders
// ---------------------------------------------------------------------------

func (s *Server) listFoldersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordRequestMetadata(r)
	// Return a JSON array containing the folder fixture.
	s.writeJSON(w, http.StatusOK, "["+folderResponseFixture+"]")
}

// ---------------------------------------------------------------------------
// POST /folders
// ---------------------------------------------------------------------------

func (s *Server) createFolderHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordJSONBody(r)
	s.writeJSON(w, http.StatusOK, folderResponseFixture)
}

// ---------------------------------------------------------------------------
// PUT /folders/{id}
// ---------------------------------------------------------------------------

func (s *Server) updateFolderHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordJSONBody(r)
	s.writeJSON(w, http.StatusOK, folderResponseFixture)
}

// ---------------------------------------------------------------------------
// DELETE /folders/{id}
// ---------------------------------------------------------------------------

func (s *Server) deleteFolderHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordRequestMetadata(r)
	s.writeEmpty(w, http.StatusOK)
}

// ---------------------------------------------------------------------------
// POST /ciphers/{cipherID}/attachment/v2  — create attachment (direct or external)
// POST /ciphers/{cipherID}/attachment     — legacy create attachment
// ---------------------------------------------------------------------------

func (s *Server) createAttachmentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}

	// Record the request — for attachment upload bodies we do NOT read raw
	// content, just record method/path/content-type/auth-present.
	s.recordAttachmentUpload(r)

	switch {
	case s.scenario.DirectAttachmentUpload:
		s.writeJSON(w, http.StatusOK, attachmentUploadDirectResponse)
	case s.scenario.ExternalAttachmentUpload:
		// Inject the server URL so the external upload URL points back to us.
		body := fmt.Sprintf(attachmentUploadAzureResponseTemplate, s.srv.URL)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	default:
		s.writeJSON(w, http.StatusOK, attachmentUploadDirectResponse)
	}
}

// ---------------------------------------------------------------------------
// POST / PUT /ciphers/{cipherID}/attachment/{attachmentID}  — direct upload
// ---------------------------------------------------------------------------

func (s *Server) uploadAttachmentContentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}

	// Record metadata only — do NOT read or store the multipart body.
	s.recordAttachmentUpload(r)

	// Return 200 (or 204) on success.
	s.writeEmpty(w, http.StatusOK)
}

// ---------------------------------------------------------------------------
// PUT / POST /external-attachment-upload/{id}  — external (Azure-style) upload
// ---------------------------------------------------------------------------

func (s *Server) externalAttachmentUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Record metadata only — do NOT read or store the raw body.
	s.recordRequestMetadata(r)

	// Return 200 on success.
	s.writeEmpty(w, http.StatusOK)
}

// ---------------------------------------------------------------------------
// GET /accounts/revision-date
// ---------------------------------------------------------------------------

func (s *Server) accountRevisionDateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordRequestMetadata(r)
	s.writeJSON(w, http.StatusOK, accountRevisionDateResponse)
}

// ---------------------------------------------------------------------------
// DELETE /ciphers/{cipherID}/attachment/{attachmentID}
// ---------------------------------------------------------------------------

func (s *Server) deleteAttachmentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	s.recordRequestMetadata(r)
	s.writeJSON(w, http.StatusOK, attachmentDeleteResponse)
}
