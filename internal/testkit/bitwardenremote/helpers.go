package bitwardenremote

import (
	"net/http"
	"testing"

	adaptershttp "github.com/bnema/bitwarden-go-sdk/internal/adapters/http"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// HTTPClient returns an *http.Client pre-configured to connect to the test
// server. It uses the httptest.Server's client, which handles TLS when the
// server uses HTTPS.
func (s *Server) HTTPClient() *http.Client {
	return s.srv.Client()
}

// NewIdentityClient creates a ports.IdentityClient wired to this test server.
// It is a convenience helper for integration tests that need a real HTTP
// identity adapter pointed at the testkit.
func (s *Server) NewIdentityClient(t testing.TB) ports.IdentityClient {
	t.Helper()
	client, err := adaptershttp.NewIdentityClient(s.IdentityURL(), s.HTTPClient())
	if err != nil {
		t.Fatalf("NewIdentityClient: %v", err)
	}
	return client
}

// ---------------------------------------------------------------------------
// Placeholder scenario options for future phases
//
// These methods or options will be fleshed out when the corresponding features
// are implemented. For now they are documented here as forward references.
//
//  - SyncReady           — the server returns a valid /sync response
//  - CipherWriteReady    — the server accepts cipher create / update / delete
//  - FolderWriteReady    — the server accepts folder create / update / delete
//  - AccountReady        — the server returns a valid /accounts/profile
//  - AttachmentReady     — the server accepts attachment upload / download
// ---------------------------------------------------------------------------
