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
	adaptercrypto "github.com/bnema/bitwarden-go-sdk/internal/adapters/crypto"
	adapterhttp "github.com/bnema/bitwarden-go-sdk/internal/adapters/http"
	"github.com/bnema/bitwarden-go-sdk/internal/adapters/memory"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	corevault "github.com/bnema/bitwarden-go-sdk/internal/core/vault"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// Client is the public Bitwarden SDK facade.
type Client struct {
	environment  config.Environment
	httpClient   *http.Client
	logger       *slog.Logger
	identity     ports.IdentityClient
	crypto       ports.CryptoEngine
	tokens       ports.TokenStore
	api          ports.APIClient
	mu           sync.Mutex
	accountID    string
	userKey      ports.UserKey
	closed       bool
	locked       atomic.Bool
	vaultService *corevault.Service
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

	crypto := cfg.crypto
	if crypto == nil {
		crypto = adaptercrypto.NewEngine()
	}

	tokens := cfg.tokens
	if tokens == nil {
		tokens = memory.NewTokenStore()
	}

	client := &Client{
		environment: env,
		httpClient:  cfg.httpClient,
		logger:      cfg.logger,
		identity:    identity,
		crypto:      crypto,
		tokens:      tokens,
	}
	client.locked.Store(true)

	// Build API client if not injected.
	api := cfg.api
	if api == nil {
		tokenProvider := func(ctx context.Context) (ports.SecretBytes, error) {
			client.mu.Lock()
			accountID := client.accountID
			client.mu.Unlock()
			if accountID == "" {
				return ports.SecretBytes{}, &coreerrors.Error{
					Kind:    coreerrors.KindValidation,
					Op:      "http.VaultClient",
					Message: "no account logged in",
				}
			}
			tokens, err := client.tokens.LoadTokens(ctx, accountID)
			if err != nil {
				return ports.SecretBytes{}, err
			}
			return tokens.AccessToken.Clone(), nil
		}
		api, err = adapterhttp.NewVaultClient(env.API, cfg.httpClient, tokenProvider)
		if err != nil {
			return nil, fmt.Errorf("bitwarden: %w", err)
		}
	}
	client.api = api

	client.vaultService = corevault.NewService(corevault.Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: client.userKey,
		Locked:  true,
	})

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

// Sync refreshes local vault state by fetching and decrypting cipher data from
// the server.
func (c *Client) Sync(ctx context.Context) error {
	if c.IsLocked() {
		return mapCoreError(&coreerrors.Error{
			Kind:    coreerrors.KindLocked,
			Op:      "Client.Sync",
			Message: "client is locked",
		})
	}
	return mapCoreError(c.vaultService.Sync(ctx))
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
	c.vaultService.Clear()
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
	c.vaultService.Clear()
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
	c.vaultService.Clear()
	return nil
}

func (c *Client) hasAccount() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accountID != ""
}

// vaultItem maps a core vault.Item to a public bitwarden.Item.
func (c *Client) vaultItem(item corevault.Item) Item {
	pub := Item{
		ID:       ItemID(item.ID),
		Name:     item.Name,
		Notes:    item.Notes,
		Favorite: item.Favorite,
		FolderID: item.FolderID,
	}

	switch item.Type {
	case corevault.TypeLogin:
		pub.Type = ItemTypeLogin
	case corevault.TypeSecureNote:
		pub.Type = ItemTypeSecureNote
	case corevault.TypeCard:
		pub.Type = ItemTypeCard
	case corevault.TypeIdentity:
		pub.Type = ItemTypeIdentity
	default:
		pub.Type = ItemType(fmt.Sprintf("type_%d", item.Type))
	}

	if item.Login != nil {
		pub.Username = item.Login.Username
		if len(item.Login.URIs) > 0 {
			pub.URI = item.Login.URIs[0].URI
			pub.URIs = make([]string, len(item.Login.URIs))
			for i, u := range item.Login.URIs {
				pub.URIs[i] = u.URI
			}
		}
		if item.Login.Password != "" {
			pub.Password = NewSecretString(item.Login.Password)
		}
		if item.Login.TOTP != "" {
			pub.TOTP = NewSecretString(item.Login.TOTP)
		}
	}

	if len(item.Fields) > 0 {
		pub.Fields = make([]Field, len(item.Fields))
		for i, f := range item.Fields {
			pub.Fields[i] = Field{
				Name:     f.Name,
				Value:    f.Value,
				Type:     f.Type,
				LinkedID: f.LinkedID,
			}
		}
	}

	if item.Card != nil {
		pub.Card = &Card{
			CardholderName: item.Card.CardholderName,
			Brand:          item.Card.Brand,
			ExpMonth:       item.Card.ExpMonth,
			ExpYear:        item.Card.ExpYear,
		}
		if item.Card.Number != "" {
			pub.Card.Number = NewSecretString(item.Card.Number)
		}
		if item.Card.Code != "" {
			pub.Card.Code = NewSecretString(item.Card.Code)
		}
	}

	if item.Identity != nil {
		pub.Identity = &Identity{
			Title:      item.Identity.Title,
			FirstName:  item.Identity.FirstName,
			MiddleName: item.Identity.MiddleName,
			LastName:   item.Identity.LastName,
			Address1:   item.Identity.Address1,
			Address2:   item.Identity.Address2,
			Address3:   item.Identity.Address3,
			City:       item.Identity.City,
			State:      item.Identity.State,
			PostalCode: item.Identity.PostalCode,
			Country:    item.Identity.Country,
			Company:    item.Identity.Company,
			Email:      item.Identity.Email,
			Phone:      item.Identity.Phone,
			Username:   item.Identity.Username,
		}
		if item.Identity.SSN != "" {
			pub.Identity.SSN = NewSecretString(item.Identity.SSN)
		}
		if item.Identity.PassportNumber != "" {
			pub.Identity.PassportNumber = NewSecretString(item.Identity.PassportNumber)
		}
		if item.Identity.LicenseNumber != "" {
			pub.Identity.LicenseNumber = NewSecretString(item.Identity.LicenseNumber)
		}
	}

	return pub
}

// vaultItems maps a slice of core vault.Items to public bitwarden.Items.
func (c *Client) vaultItems(items []corevault.Item) []Item {
	if items == nil {
		return nil
	}
	result := make([]Item, len(items))
	for i, item := range items {
		result[i] = c.vaultItem(item)
	}
	return result
}

// Vault is the public facade for vault item operations.
type Vault struct {
	client *Client
}

// List returns all vault items.
func (v *Vault) List(_ context.Context) ([]Item, error) {
	if v.client.IsLocked() && v.client.hasAccount() {
		return nil, mapCoreError(&coreerrors.Error{Kind: coreerrors.KindLocked, Op: "Vault.List", Message: "client is locked"})
	}
	items, err := v.client.vaultService.List()
	if err != nil {
		return nil, mapCoreError(err)
	}
	return v.client.vaultItems(items), nil
}

// Search finds vault items whose safe fields contain query (case-insensitive).
func (v *Vault) Search(_ context.Context, query string) ([]Item, error) {
	if v.client.IsLocked() && v.client.hasAccount() {
		return nil, mapCoreError(&coreerrors.Error{Kind: coreerrors.KindLocked, Op: "Vault.Search", Message: "client is locked"})
	}
	items, err := v.client.vaultService.Search(query)
	if err != nil {
		return nil, mapCoreError(err)
	}
	return v.client.vaultItems(items), nil
}

// Get returns a vault item by ID.
func (v *Vault) Get(_ context.Context, id ItemID) (Item, error) {
	if v.client.IsLocked() && v.client.hasAccount() {
		return Item{}, mapCoreError(&coreerrors.Error{Kind: coreerrors.KindLocked, Op: "Vault.Get", Message: "client is locked"})
	}
	item, ok, err := v.client.vaultService.Get(string(id))
	if err != nil {
		return Item{}, mapCoreError(err)
	}
	if !ok {
		return Item{}, mapCoreError(&coreerrors.Error{
			Kind:    coreerrors.KindNotFound,
			Op:      "Vault.Get",
			Message: fmt.Sprintf("item %q not found", string(id)),
		})
	}
	return v.client.vaultItem(item), nil
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
