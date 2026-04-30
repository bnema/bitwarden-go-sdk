package bitwarden

import (
	"context"

	adaptercrypto "github.com/bnema/bitwarden-go-sdk/internal/adapters/crypto"
	"github.com/bnema/bitwarden-go-sdk/internal/adapters/memory"
	coreauth "github.com/bnema/bitwarden-go-sdk/internal/core/auth"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
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
