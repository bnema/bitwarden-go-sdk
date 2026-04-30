package bitwarden

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// clientConfig collects option values before the Client is built.
type clientConfig struct {
	region     Region
	regionSet  bool // true when WithRegion was explicitly called
	serverURL  string
	httpClient *http.Client
	logger     *slog.Logger
	identity   ports.IdentityClient
	crypto     ports.CryptoEngine
	tokens     ports.TokenStore
	api        ports.APIClient
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

// withIdentityClient injects an identity client. It is intended for tests and
// local-first adapters; production callers normally rely on SDK defaults.
func withIdentityClient(identity ports.IdentityClient) Option {
	return func(cfg *clientConfig) error {
		cfg.identity = identity
		return nil
	}
}

// withCryptoEngine injects a crypto engine. It is intended for tests.
func withCryptoEngine(crypto ports.CryptoEngine) Option {
	return func(cfg *clientConfig) error {
		cfg.crypto = crypto
		return nil
	}
}

// WithTokenStore injects a token store for persisting OAuth tokens.
// Use this to provide your own persistent storage (e.g. keyring, file, DB)
// instead of the default in-memory store.
func WithTokenStore(store TokenStore) Option {
	return func(cfg *clientConfig) error {
		if store != nil {
			cfg.tokens = &tokenStoreAdapter{pub: store}
		}
		return nil
	}
}

// withTokenStore injects a token store. TokenStore is a sensitive boundary.
func withTokenStore(tokens ports.TokenStore) Option {
	return func(cfg *clientConfig) error {
		cfg.tokens = tokens
		return nil
	}
}

// withAPIClient injects an API client. It is intended for tests.
func withAPIClient(api ports.APIClient) Option {
	return func(cfg *clientConfig) error {
		cfg.api = api
		return nil
	}
}
