package bitwarden

import (
	"context"

	adaptercrypto "github.com/bnema/bitwarden-go-sdk/internal/adapters/crypto"
	"github.com/bnema/bitwarden-go-sdk/internal/adapters/memory"
	coreauth "github.com/bnema/bitwarden-go-sdk/internal/core/auth"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/secretmem"
)

// LoginResult reports the result of BeginLogin.
type LoginResult struct {
	AccountID string
	Challenge *TwoFactorChallenge
}

// TwoFactorChallenge contains supported providers and opaque continuation state.
type TwoFactorChallenge struct {
	providers []TwoFactorProvider
	core      coreauth.TwoFactorChallenge
}

// Providers returns the supported providers for this challenge.
func (c *TwoFactorChallenge) Providers() []TwoFactorProvider {
	if c == nil {
		return nil
	}
	out := make([]TwoFactorProvider, len(c.providers))
	copy(out, c.providers)
	return out
}

// Close zeros sensitive continuation material. Callers that abandon a two-factor
// challenge without completing login should call Close.
func (c *TwoFactorChallenge) Close() {
	if c == nil {
		return
	}
	c.core.Close()
}

// CompleteLoginOptions contains a two-factor login completion request.
type CompleteLoginOptions struct {
	Challenge *TwoFactorChallenge
	Provider  TwoFactorProvider
	Code      string
	Remember  bool
}

// BeginLogin starts master-password login and may return a two-factor challenge.
func (c *Client) BeginLogin(ctx context.Context, options LoginOptions) (LoginResult, error) {
	svc := c.authService()
	input := coreauth.LoginInput{
		Email:            options.Email,
		Password:         options.Password,
		DeviceType:       options.DeviceType,
		DeviceIdentifier: options.DeviceIdentifier,
		DeviceName:       options.DeviceName,
	}
	result, err := svc.BeginLogin(ctx, input)
	if err != nil {
		return LoginResult{}, mapCoreError(err)
	}
	if result.Challenge != nil {
		return LoginResult{Challenge: publicChallenge(*result.Challenge)}, nil
	}
	if result.Login == nil {
		return LoginResult{}, nil
	}
	c.mu.Lock()
	c.userKey.Close()
	c.accountID = result.Login.AccountID
	c.userKey = result.Login.UserKey
	c.mu.Unlock()
	c.locked.Store(false)
	c.vaultService.SetUserKey(result.Login.UserKey)
	c.vaultService.SetLocked(false)
	return LoginResult{AccountID: result.Login.AccountID}, nil
}

// CompleteLogin completes a two-factor challenge returned by BeginLogin.
func (c *Client) CompleteLogin(ctx context.Context, options CompleteLoginOptions) (LoginResult, error) {
	if options.Challenge == nil {
		return LoginResult{}, &Error{Kind: ErrorKindValidation, Op: "Client.CompleteLogin", Code: "missing_challenge", Message: "challenge is required"}
	}
	svc := c.authService()
	defer options.Challenge.Close()
	result, err := svc.CompleteTwoFactor(ctx, options.Challenge.core, coreProvider(options.Provider), options.Code, options.Remember)
	if err != nil {
		return LoginResult{}, mapCoreError(err)
	}
	c.mu.Lock()
	c.userKey.Close()
	c.accountID = result.AccountID
	c.userKey = result.UserKey
	c.mu.Unlock()
	c.locked.Store(false)
	c.vaultService.SetUserKey(result.UserKey)
	c.vaultService.SetLocked(false)
	return LoginResult{AccountID: result.AccountID}, nil
}

func (c *Client) authService() *coreauth.Service {
	identity := c.identity
	crypto := c.crypto
	tokens := c.tokens
	if crypto == nil {
		crypto = adaptercrypto.NewEngine()
	}
	if tokens == nil {
		tokens = memory.NewTokenStore()
	}
	return coreauth.NewService(coreauth.Dependencies{Identity: identity, Crypto: crypto, Tokens: tokens})
}

func publicChallenge(challenge coreauth.TwoFactorChallenge) *TwoFactorChallenge {
	providers := make([]TwoFactorProvider, len(challenge.Providers))
	for i, provider := range challenge.Providers {
		providers[i] = publicProvider(provider)
	}
	return &TwoFactorChallenge{providers: providers, core: challenge}
}

func publicProvider(provider ports.TwoFactorProvider) TwoFactorProvider {
	switch provider {
	case ports.TwoFactorProviderAuthenticator:
		return TwoFactorProviderAuthenticator
	case ports.TwoFactorProviderEmail:
		return TwoFactorProviderEmail
	case ports.TwoFactorProviderYubiKey:
		return TwoFactorProviderYubiKey
	case ports.TwoFactorProviderDuo:
		return TwoFactorProviderDuo
	default:
		return TwoFactorProvider(provider)
	}
}

func coreProvider(provider TwoFactorProvider) ports.TwoFactorProvider {
	switch provider {
	case TwoFactorProviderAuthenticator:
		return ports.TwoFactorProviderAuthenticator
	case TwoFactorProviderEmail:
		return ports.TwoFactorProviderEmail
	case TwoFactorProviderYubiKey:
		return ports.TwoFactorProviderYubiKey
	case TwoFactorProviderDuo:
		return ports.TwoFactorProviderDuo
	default:
		return ports.TwoFactorProvider(provider)
	}
}

// ExportSession returns the current unlocked session material including
// account ID, user key, and tokens. Returns an error when the client is
// locked or no account is logged in.
func (c *Client) ExportSession(ctx context.Context) (SessionMaterial, error) {
	if c.IsLocked() {
		return SessionMaterial{}, mapCoreError(&coreerrors.Error{
			Kind:    coreerrors.KindLocked,
			Op:      "Client.ExportSession",
			Message: "client is locked",
		})
	}
	c.mu.Lock()
	accountID := c.accountID
	userKeyBytes := secretmem.Clone(c.userKey.Bytes)
	c.mu.Unlock()
	if accountID == "" {
		secretmem.Zero(userKeyBytes)
		return SessionMaterial{}, mapCoreError(&coreerrors.Error{
			Kind:    coreerrors.KindValidation,
			Op:      "Client.ExportSession",
			Code:    "no_account",
			Message: "no account logged in",
		})
	}
	tokens, err := c.tokens.LoadTokens(ctx, accountID)
	if err != nil {
		secretmem.Zero(userKeyBytes)
		return SessionMaterial{}, mapCoreError(err)
	}
	return SessionMaterial{
		AccountID: accountID,
		UserKey:   userKeyBytes,
		Tokens:    tokenSetFromPorts(tokens),
	}, nil
}

// RestoreSession restores the client to an unlocked state from the given
// session material. It validates the account ID and user key, deep-copies
// secrets, saves tokens when present, and sets vault service state.
func (c *Client) RestoreSession(ctx context.Context, material SessionMaterial) error {
	if material.AccountID == "" {
		return mapCoreError(&coreerrors.Error{
			Kind:    coreerrors.KindValidation,
			Op:      "Client.RestoreSession",
			Code:    "missing_account_id",
			Message: "account ID is required",
		})
	}
	if len(material.UserKey) == 0 {
		return mapCoreError(&coreerrors.Error{
			Kind:    coreerrors.KindValidation,
			Op:      "Client.RestoreSession",
			Code:    "missing_user_key",
			Message: "user key is required",
		})
	}
	clone := material.Clone()
	defer clone.Close()
	if len(clone.Tokens.AccessToken) > 0 || len(clone.Tokens.RefreshToken) > 0 {
		tokens := clone.Tokens
		if tokens.AccountID == "" {
			tokens.AccountID = clone.AccountID
		} else if tokens.AccountID != clone.AccountID {
			return mapCoreError(&coreerrors.Error{
				Kind:    coreerrors.KindValidation,
				Op:      "Client.RestoreSession",
				Code:    "token_account_id_mismatch",
				Message: "token account ID does not match session account ID",
			})
		}
		if err := c.tokens.SaveTokens(ctx, tokenSetToPorts(tokens)); err != nil {
			return mapCoreError(err)
		}
	}
	c.mu.Lock()
	c.accountID = clone.AccountID
	c.userKey.Close()
	c.userKey = ports.UserKey{Bytes: secretmem.Clone(clone.UserKey)}
	c.mu.Unlock()
	c.locked.Store(false)
	c.vaultService.SetUserKey(ports.UserKey{Bytes: clone.UserKey})
	c.vaultService.SetLocked(false)
	return nil
}

// RefreshSession refreshes the OAuth token set for the given account and
// returns the new tokens wrapped in a RefreshResult. Concurrent calls for
// the same account are deduplicated to a single identity round-trip.
func (c *Client) RefreshSession(ctx context.Context, accountID string) (RefreshResult, error) {
	tokens, err := c.refreshCoordinator.Refresh(ctx, accountID)
	if err != nil {
		return RefreshResult{}, mapCoreError(err)
	}
	return RefreshResult{Tokens: tokenSetFromPorts(tokens)}, nil
}
