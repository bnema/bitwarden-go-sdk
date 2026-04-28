package bitwarden

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// clientConfig collects option values before the Client is built.
type clientConfig struct {
	region     Region
	regionSet  bool // true when WithRegion was explicitly called
	serverURL  string
	httpClient *http.Client
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*clientConfig) error

// WithRegion sets the Bitwarden region.
func WithRegion(region Region) Option {
	return func(cfg *clientConfig) error {
		switch region {
		case RegionUS, RegionEU:
			cfg.region = region
			cfg.regionSet = true
			return nil
		default:
			return fmt.Errorf("bitwarden: unknown region: %q", region)
		}
	}
}

// WithServerURL sets an explicit self-hosted server base URL.
func WithServerURL(baseURL string) Option {
	return func(cfg *clientConfig) error {
		if baseURL == "" {
			return errors.New("bitwarden: server URL must not be empty")
		}
		cfg.serverURL = baseURL
		return nil
	}
}

// WithBaseURL is a deprecated alias for WithServerURL.
// Deprecated: use WithServerURL instead.
func WithBaseURL(baseURL string) Option {
	return WithServerURL(baseURL)
}

// WithHTTPClient sets the HTTP client used by the SDK.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(cfg *clientConfig) error {
		if httpClient != nil {
			cfg.httpClient = httpClient
		}
		return nil
	}
}

// WithLogger sets the structured logger used by the SDK.
func WithLogger(logger *slog.Logger) Option {
	return func(cfg *clientConfig) error {
		if logger != nil {
			cfg.logger = logger
		}
		return nil
	}
}
