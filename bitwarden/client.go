package bitwarden

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
)

type Client struct {
	region     Region
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
	locked     atomic.Bool
}

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

func (c *Client) Login(ctx context.Context, options LoginOptions) error {
	_ = ctx
	_ = options
	return ErrUnsupported
}

func (c *Client) Sync(ctx context.Context) error {
	_ = ctx
	return ErrUnsupported
}

func (c *Client) Vault() *Vault {
	return &Vault{client: c}
}

func (c *Client) Lock() {
	c.locked.Store(true)
}

func (c *Client) IsLocked() bool {
	return c.locked.Load()
}

func (c *Client) Close() error {
	c.Lock()
	return nil
}

type Vault struct {
	client *Client
}

func (v *Vault) Search(ctx context.Context, query string) ([]Item, error) {
	_ = ctx
	_ = query
	return nil, ErrUnsupported
}

func (v *Vault) Get(ctx context.Context, id ItemID) (Item, error) {
	_ = ctx
	_ = id
	return Item{}, ErrUnsupported
}

func (v *Vault) Password(ctx context.Context, id ItemID) (string, error) {
	_ = ctx
	_ = id
	return "", ErrUnsupported
}
