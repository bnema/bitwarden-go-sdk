// Package bitwardenremote provides test scenario definitions and safe request
// recording for simulating a Bitwarden server in integration tests without
// leaking sensitive data.
package bitwardenremote

import (
	"time"
)

// ---------------------------------------------------------------------------
// Scenario — high-level test scenario configuration
// ---------------------------------------------------------------------------

// Scenario describes which Bitwarden server behaviour the test harness should
// simulate.
type Scenario struct {
	// TwoFactorProvider, when non-empty, instructs the server to reply with a
	// 2FA challenge for the given provider (e.g. "email", "authenticator").
	TwoFactorProvider string

	// ExpiredAccessToken, when true, makes the server reject requests with a
	// 401 "expired access token" response.
	ExpiredAccessToken bool

	// RateLimit configures the server to respond with HTTP 429. The value is
	// the Retry-After duration in seconds that the server announces.
	RateLimit struct {
		Enabled    bool
		RetryAfter time.Duration
	}

	// DirectAttachmentUpload, when true, makes the server expect the SDK to
	// upload attachment data directly via the API (single-step). The server
	// responds with a pre-signed URL.
	DirectAttachmentUpload bool

	// ExternalAttachmentUpload, when true, makes the server hand back an
	// external upload URL that the SDK must PUT the attachment data to
	// (two-step).
	ExternalAttachmentUpload bool
}

// NewScenario creates a default personal-vault Scenario and applies the
// supplied options.
func NewScenario(opts ...ScenarioOption) Scenario {
	s := Scenario{}
	for _, opt := range opts {
		opt(&s)
	}
	return s
}

// ScenarioOption mutates a Scenario.
type ScenarioOption func(*Scenario)

// WithTwoFactorProvider configures the server to require two-factor
// authentication with the given provider.
func WithTwoFactorProvider(provider string) ScenarioOption {
	return func(s *Scenario) {
		s.TwoFactorProvider = provider
	}
}

// WithExpiredAccessToken configures the server to reject requests with an
// expired access token error.
func WithExpiredAccessToken() ScenarioOption {
	return func(s *Scenario) {
		s.ExpiredAccessToken = true
	}
}

// WithRateLimit configures the server to respond with HTTP 429 and the given
// Retry-After value in seconds.
func WithRateLimit(retryAfterSeconds int) ScenarioOption {
	return func(s *Scenario) {
		s.RateLimit.Enabled = true
		s.RateLimit.RetryAfter = time.Duration(retryAfterSeconds) * time.Second
	}
}

// WithDirectAttachmentUpload configures the server to use single-step
// (direct) attachment upload.
func WithDirectAttachmentUpload() ScenarioOption {
	return func(s *Scenario) {
		s.DirectAttachmentUpload = true
	}
}

// WithExternalAttachmentUpload configures the server to use two-step
// (external) attachment upload.
func WithExternalAttachmentUpload() ScenarioOption {
	return func(s *Scenario) {
		s.ExternalAttachmentUpload = true
	}
}
