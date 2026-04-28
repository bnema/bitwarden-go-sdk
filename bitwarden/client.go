package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/bnema/bitwarden-go-sdk/internal/adapters/config"
	adapterhttp "github.com/bnema/bitwarden-go-sdk/internal/adapters/http"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// Client is the public Bitwarden SDK facade.
type Client struct {
	environment config.Environment
	httpClient  *http.Client
	logger      *slog.Logger
	identity    ports.IdentityClient
	crypto      ports.CryptoEngine
	tokens      ports.TokenStore
	mu          sync.Mutex
	accountID   string
	userKey     ports.UserKey
	closed      bool
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

	identity := cfg.identity
	if identity == nil {
		identity, err = adapterhttp.NewIdentityClient(env.Identity, cfg.httpClient)
		if err != nil {
			return nil, fmt.Errorf("bitwarden: %w", err)
		}
	}

	client := &Client{
		environment: env,
		httpClient:  cfg.httpClient,
		logger:      cfg.logger,
		identity:    identity,
		crypto:      cfg.crypto,
		tokens:      cfg.tokens,
	}
	client.locked.Store(true)
	return client, nil
}

// Login authenticates the client without exposing a two-factor challenge.
func (c *Client) Login(ctx context.Context, options LoginOptions) error {
	result, err := c.BeginLogin(ctx, options)
	if err != nil {
		return err
	}
	if result.Challenge != nil {
		result.Challenge.Close()
		return &Error{Kind: ErrorKindTwoFactorRequired, Op: "Client.Login", Message: "two-factor authentication required"}
	}
	return nil
}

// Sync refreshes local vault state when real behavior is implemented.
func (c *Client) Sync(ctx context.Context) error {
	_ = ctx
	return mapCoreError(&coreerrors.Error{
		Kind:    coreerrors.KindUnsupported,
		Op:      "Client.Sync",
		Message: "sync not yet implemented",
	})
}

// Vault returns the vault facade for item operations.
func (c *Client) Vault() *Vault {
	return &Vault{client: c}
}

// Lock marks the client as locked and clears in-memory key material.
func (c *Client) Lock() {
	c.mu.Lock()
	c.userKey.Close()
	c.mu.Unlock()
	c.locked.Store(true)
}

// IsLocked reports whether the client is locked.
func (c *Client) IsLocked() bool {
	return c.locked.Load()
}

// Logout clears stored tokens for the current account and locks the client.
func (c *Client) Logout(ctx context.Context) error {
	c.mu.Lock()
	accountID := c.accountID
	c.accountID = ""
	c.userKey.Close()
	c.mu.Unlock()
	c.locked.Store(true)
	if accountID != "" && c.tokens != nil {
		if err := c.tokens.DeleteTokens(ctx, accountID); err != nil {
			return mapCoreError(err)
		}
	}
	return nil
}

// Close releases client state held by the SDK. It is idempotent.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.userKey.Close()
	c.mu.Unlock()
	c.locked.Store(true)
	return nil
}

func (c *Client) hasAccount() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accountID != ""
}

// Vault is the public facade for vault item operations.
type Vault struct {
	client *Client
}

// Search finds vault items when real behavior is implemented.
func (v *Vault) Search(ctx context.Context, query string) ([]Item, error) {
	_ = ctx
	_ = query
	if v.client.IsLocked() && v.client.hasAccount() {
		return nil, mapCoreError(&coreerrors.Error{Kind: coreerrors.KindLocked, Op: "Vault.Search", Message: "client is locked"})
	}
	return nil, mapCoreError(&coreerrors.Error{
		Kind:    coreerrors.KindUnsupported,
		Op:      "Vault.Search",
		Message: "search not yet implemented",
	})
}

// Get returns a vault item when real behavior is implemented.
func (v *Vault) Get(ctx context.Context, id ItemID) (Item, error) {
	_ = ctx
	_ = id
	if v.client.IsLocked() && v.client.hasAccount() {
		return Item{}, mapCoreError(&coreerrors.Error{Kind: coreerrors.KindLocked, Op: "Vault.Get", Message: "client is locked"})
	}
	return Item{}, mapCoreError(&coreerrors.Error{
		Kind:    coreerrors.KindUnsupported,
		Op:      "Vault.Get",
		Message: "get not yet implemented",
	})
}

// Password returns an item's password when real behavior is implemented.
func (v *Vault) Password(ctx context.Context, id ItemID) (string, error) {
	_ = ctx
	_ = id
	if v.client.IsLocked() && v.client.hasAccount() {
		return "", mapCoreError(&coreerrors.Error{Kind: coreerrors.KindLocked, Op: "Vault.Password", Message: "client is locked"})
	}
	return "", mapCoreError(&coreerrors.Error{
		Kind:    coreerrors.KindUnsupported,
		Op:      "Vault.Password",
		Message: "password not yet implemented",
	})
}
