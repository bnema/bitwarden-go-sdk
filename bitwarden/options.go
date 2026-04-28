package bitwarden

import (
	"log/slog"
	"net/http"
)

// Option configures a Client.
type Option func(*Client)

// WithRegion sets the Bitwarden region.
func WithRegion(region Region) Option {
	return func(c *Client) {
		c.region = region
	}
}

// WithBaseURL sets an explicit service base URL.
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		c.baseURL = baseURL
	}
}

// WithHTTPClient sets the HTTP client used by the SDK.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

// WithLogger sets the structured logger used by the SDK.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) {
		if logger != nil {
			c.logger = logger
		}
	}
}
