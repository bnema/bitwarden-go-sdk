// Package bitwardenremote provides a test HTTP server that simulates
// Bitwarden identity and API endpoints for integration tests.
package bitwardenremote

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Server is a lightweight Bitwarden server simulator for integration tests.
// It serves identity endpoints and records request metadata via Recorder.
type Server struct {
	t        testing.TB
	scenario Scenario
	recorder *Recorder
	srv      *httptest.Server
	mux      *http.ServeMux
}

// NewServer creates and starts a new test server configured with the given
// Scenario. The server is shut down automatically when the test finishes.
func NewServer(t testing.TB, scenario Scenario) *Server {
	t.Helper()

	s := &Server{
		t:        t,
		scenario: scenario,
		recorder: NewRecorder(),
		mux:      http.NewServeMux(),
	}

	s.registerRoutes()

	s.srv = httptest.NewServer(s.mux)
	t.Cleanup(s.srv.Close)

	return s
}

// Close shuts down the test server.
func (s *Server) Close() {
	if s.srv != nil {
		s.srv.Close()
	}
}

// IdentityURL returns the base URL of the test server, suitable for use as
// a Bitwarden identity server URL.
func (s *Server) IdentityURL() string {
	return s.srv.URL
}

// Recorder returns the request recorder attached to this server.
func (s *Server) Recorder() *Recorder {
	return s.recorder
}

// registerRoutes sets up the HTTP handler for every supported endpoint.
func (s *Server) registerRoutes() {
	// Identity / auth routes
	s.mux.HandleFunc("/accounts/prelogin/password", s.preloginHandler)
	s.mux.HandleFunc("/connect/token", s.tokenHandler)

	// Config
	s.mux.HandleFunc("/config", s.configHandler)

	// Account profile & subscription
	s.mux.HandleFunc("/accounts/profile", s.accountProfileHandler)
	s.mux.HandleFunc("/plans/subscription", s.subscriptionHandler)
	s.mux.HandleFunc("/accounts/subscription", s.subscriptionHandler)

	// Account revision date
	s.mux.HandleFunc("/accounts/revision-date", s.accountRevisionDateHandler)

	// External attachment upload (self-contained local URL)
	s.mux.Handle("/external-attachment-upload/", http.HandlerFunc(s.externalAttachmentUploadHandler))

	// Attachment download (self-contained local URL, no auth required)
	s.mux.Handle("/attachment-download/", http.HandlerFunc(s.attachmentDownloadContentHandler))

	// Sync
	s.mux.HandleFunc("/sync", s.syncHandler)
	s.mux.HandleFunc("/sync/revision-date", s.syncRevisionDateHandler)

	// Ciphers — exact match for POST /ciphers only
	s.mux.HandleFunc("/ciphers", s.createCipherHandler)

	// Ciphers sub-routes — subtree pattern catches everything under /ciphers/
	s.mux.Handle("/ciphers/", http.HandlerFunc(s.cipherPathRouter))

	// Folders — exact match (dispatches GET and POST by method)
	s.mux.HandleFunc("/folders", s.foldersExactRouter)

	// Folders sub-routes — subtree pattern catches /folders/{id}, etc.
	s.mux.Handle("/folders/", http.HandlerFunc(s.folderPathRouter))

}

// cipherPathRouter dispatches to the appropriate cipher sub-handler based on
// the request path (under /ciphers/).
func (s *Server) cipherPathRouter(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/ciphers/delete":
		s.bulkDeleteCiphersHandler(w, r)

	case strings.HasSuffix(path, "/restore"):
		s.restoreCipherHandler(w, r)

	case strings.HasSuffix(path, "/delete"):
		s.trashCipherHandler(w, r)

	case strings.HasSuffix(path, "/attachment/v2"), strings.HasSuffix(path, "/attachment"):
		s.createAttachmentHandler(w, r)

	case strings.Contains(path, "/attachment/"):
		s.attachmentPathRouter(w, r)

	default:
		// /ciphers/{id} — dispatch by method
		switch r.Method {
		case http.MethodPut:
			s.updateCipherHandler(w, r)
		case http.MethodDelete:
			s.deleteCipherHandler(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// foldersExactRouter dispatches GET /folders and POST /folders.
func (s *Server) foldersExactRouter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listFoldersHandler(w, r)
	case http.MethodPost:
		s.createFolderHandler(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// folderPathRouter dispatches based on the path under /folders/.
func (s *Server) folderPathRouter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		s.updateFolderHandler(w, r)
	case http.MethodDelete:
		s.deleteFolderHandler(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// attachmentPathRouter dispatches based on the path under /ciphers/.../attachment/.
//   - DELETE                             -> deleteAttachmentHandler
//   - GET with /renew suffix             -> renewAttachmentUploadURLHandler
//   - GET                                -> getAttachmentMetadataHandler
//   - POST/PUT                           -> uploadAttachmentContentHandler
func (s *Server) attachmentPathRouter(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check for /renew suffix first.
	if strings.HasSuffix(path, "/renew") && r.Method == http.MethodGet {
		s.renewAttachmentUploadURLHandler(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getAttachmentMetadataHandler(w, r)
	case http.MethodPost, http.MethodPut:
		s.uploadAttachmentContentHandler(w, r)
	case http.MethodDelete:
		s.deleteAttachmentHandler(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
