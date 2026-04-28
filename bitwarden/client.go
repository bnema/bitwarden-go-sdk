package bitwarden

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
)

// Client is the public Bitwarden SDK facade.
type Client struct {
	region     Region
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
	locked     atomic.Bool
}

// NewClient constructs a scaffold client with the supplied options.
func NewClient(options ...Option) *Client {
	client := &Client{
		region:     RegionUS,
		httpClient: http.DefaultClient,
		logger:     slog.New(slog.DiscardHandler),
	}
	client.locked.Store(true)
	for _, option := range options {
		if option != nil {
			option(client)
		}
	}
	return client
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
