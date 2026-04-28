package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/bnema/bitwarden-go-sdk/internal/adapters/config"
)

// Client is the public Bitwarden SDK facade.
type Client struct {
	environment config.Environment
	httpClient  *http.Client
	logger      *slog.Logger
	locked      atomic.Bool
}

// NewClient constructs a scaffold client with the supplied options.
func NewClient(options ...Option) (*Client, error) {
	cfg := &clientConfig{
		region:     RegionUS,
		httpClient: http.DefaultClient,
		logger:     slog.New(slog.DiscardHandler),
	}

	for _, option := range options {
		if option != nil {
			if err := option(cfg); err != nil {
				return nil, err
			}
		}
	}

	if cfg.regionSet && cfg.serverURL != "" {
		return nil, errors.New("bitwarden: cannot specify both region and server URL")
	}

	var env config.Environment
	var err error

	if cfg.serverURL != "" {
		env, err = config.NewSelfHosted(cfg.serverURL)
		if err != nil {
			return nil, fmt.Errorf("bitwarden: %w", err)
		}
	} else {
		var internalRegion config.Region
		switch cfg.region {
		case RegionUS:
			internalRegion = config.RegionUS
		case RegionEU:
			internalRegion = config.RegionEU
		default:
			return nil, fmt.Errorf("bitwarden: unknown region: %q", cfg.region)
		}
		env, err = config.NewCloud(internalRegion)
		if err != nil {
			return nil, fmt.Errorf("bitwarden: %w", err)
		}
	}

	client := &Client{
		environment: env,
		httpClient:  cfg.httpClient,
		logger:      cfg.logger,
	}
	client.locked.Store(true)
	return client, nil
}

// Login authenticates the client when real behavior is implemented.
func (c *Client) Login(ctx context.Context, options LoginOptions) error {
	_ = ctx
	_ = options
	return ErrUnsupported
}

// Sync refreshes local vault state when real behavior is implemented.
func (c *Client) Sync(ctx context.Context) error {
	_ = ctx
	return ErrUnsupported
}

// Vault returns the vault facade for item operations.
func (c *Client) Vault() *Vault {
	return &Vault{client: c}
}

// Lock marks the client as locked.
func (c *Client) Lock() {
	c.locked.Store(true)
}

// IsLocked reports whether the client is locked.
func (c *Client) IsLocked() bool {
	return c.locked.Load()
}

// Close releases client state held by the scaffold.
func (c *Client) Close() error {
	c.Lock()
	return nil
}

// Vault is the public facade for vault item operations.
type Vault struct {
	client *Client
}

// Search finds vault items when real behavior is implemented.
func (v *Vault) Search(ctx context.Context, query string) ([]Item, error) {
	_ = ctx
	_ = query
	return nil, ErrUnsupported
}

// Get returns a vault item when real behavior is implemented.
func (v *Vault) Get(ctx context.Context, id ItemID) (Item, error) {
	_ = ctx
	_ = id
	return Item{}, ErrUnsupported
}

// Password returns an item's password when real behavior is implemented.
func (v *Vault) Password(ctx context.Context, id ItemID) (string, error) {
	_ = ctx
	_ = id
	return "", ErrUnsupported
}
