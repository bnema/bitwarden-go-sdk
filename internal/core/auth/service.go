package auth

import (
	"context"
	stderrors "errors"
	"strings"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// Service orchestrates Bitwarden master-password authentication flows.
type Service struct {
	identity ports.IdentityClient
	crypto   ports.CryptoEngine
	tokens   ports.TokenStore
}

// Dependencies groups auth service dependencies.
type Dependencies struct {
	Identity ports.IdentityClient
	Crypto   ports.CryptoEngine
	Tokens   ports.TokenStore
}

// NewService constructs an auth Service.
func NewService(deps Dependencies) *Service {
	return &Service{identity: deps.Identity, crypto: deps.Crypto, tokens: deps.Tokens}
}

// LoginInput contains a master-password login request.
type LoginInput struct {
	Email            string
	Password         string
	DeviceType       string
	DeviceIdentifier string
	DeviceName       string
}

// LoginResult contains unlocked auth state returned after a successful login.
type LoginResult struct {
	AccountID string
	UserKey   ports.UserKey
	Tokens    ports.TokenSet
}

// BeginLoginResult is either a completed login or a 2FA challenge.
type BeginLoginResult struct {
	Login     *LoginResult
	Challenge *TwoFactorChallenge
}

// TwoFactorChallenge carries continuation state for classic 2FA completion.
type TwoFactorChallenge struct {
	Email            string
	AuthHash         ports.SecretBytes
	MasterKey        ports.MasterKey
	Providers        []ports.TwoFactorProvider
	DeviceType       string
	DeviceIdentifier string
	DeviceName       string
}

// Close zeros sensitive continuation material held for 2FA completion.
func (c *TwoFactorChallenge) Close() {
	if c == nil {
		return
	}
	c.AuthHash.Close()
	c.MasterKey.Close()
}

// BeginLogin performs prelogin, derives auth material, and attempts password login.
func (s *Service) BeginLogin(ctx context.Context, input LoginInput) (BeginLoginResult, error) {
	if err := ctx.Err(); err != nil {
		return BeginLoginResult{}, err
	}
	if s == nil || s.identity == nil || s.crypto == nil || s.tokens == nil {
		return BeginLoginResult{}, coreError(errors.KindValidation, "auth.BeginLogin", "missing_dependency", "auth service dependencies are required")
	}
	email := normalizeEmail(input.Email)
	if email == "" || input.Password == "" {
		return BeginLoginResult{}, coreError(errors.KindValidation, "auth.BeginLogin", "invalid_login_input", "email and password are required")
	}

	prelogin, err := s.identity.Prelogin(ctx, email)
	if err != nil {
		return BeginLoginResult{}, err
	}
	masterKey, err := s.crypto.DeriveMasterKey(ctx, ports.MasterKeyInput{Email: email, Password: input.Password, KDF: prelogin.KDF})
	if err != nil {
		return BeginLoginResult{}, err
	}
	closeMasterKey := true
	defer func() {
		if closeMasterKey {
			masterKey.Close()
		}
	}()
	authHash, err := s.crypto.MakeAuthHash(ctx, ports.AuthHashInput{Password: input.Password, MasterKey: masterKey})
	if err != nil {
		return BeginLoginResult{}, err
	}

	request := ports.PasswordTokenRequest{
		Email:            email,
		AuthHash:         string(authHash),
		DeviceType:       input.DeviceType,
		DeviceIdentifier: input.DeviceIdentifier,
		DeviceName:       input.DeviceName,
	}
	response, err := s.identity.LoginPassword(ctx, request)
	if err != nil {
		providers, ok := twoFactorProviders(err)
		if !ok {
			return BeginLoginResult{}, err
		}
		mapped, unsupported := supportedProviders(providers)
		if len(mapped) == 0 {
			return BeginLoginResult{}, &errors.Error{Kind: errors.KindUnsupported, Op: "auth.BeginLogin", Code: "unsupported_two_factor_provider", Message: "two-factor provider is unsupported", TwoFactorProviders: unsupported}
		}
		closeMasterKey = false
		return BeginLoginResult{Challenge: &TwoFactorChallenge{
			Email:            email,
			AuthHash:         ports.NewSecretBytes([]byte(authHash)),
			MasterKey:        masterKey,
			Providers:        mapped,
			DeviceType:       input.DeviceType,
			DeviceIdentifier: input.DeviceIdentifier,
			DeviceName:       input.DeviceName,
		}}, nil
	}
	login, err := s.finishLogin(ctx, masterKey, response)
	if err != nil {
		return BeginLoginResult{}, err
	}
	return BeginLoginResult{Login: &login}, nil
}

// CompleteTwoFactor completes a classic 2FA challenge returned by BeginLogin.
func (s *Service) CompleteTwoFactor(ctx context.Context, challenge TwoFactorChallenge, provider ports.TwoFactorProvider, code string, remember bool) (LoginResult, error) {
	defer challenge.Close()
	if err := ctx.Err(); err != nil {
		return LoginResult{}, err
	}
	if !challengeAllows(challenge, provider) {
		return LoginResult{}, &errors.Error{Kind: errors.KindUnsupported, Op: "auth.CompleteTwoFactor", Code: "unsupported_two_factor_provider", Message: "two-factor provider is unsupported"}
	}
	if code == "" {
		return LoginResult{}, coreError(errors.KindValidation, "auth.CompleteTwoFactor", "missing_two_factor_code", "two-factor code is required")
	}
	response, err := s.identity.CompleteTwoFactor(ctx, ports.TwoFactorTokenRequest{
		Email:            challenge.Email,
		AuthHash:         string(challenge.AuthHash.Bytes()),
		Provider:         provider,
		Code:             code,
		Remember:         remember,
		DeviceType:       challenge.DeviceType,
		DeviceIdentifier: challenge.DeviceIdentifier,
		DeviceName:       challenge.DeviceName,
	})
	if err != nil {
		return LoginResult{}, err
	}
	return s.finishLogin(ctx, challenge.MasterKey, response)
}

func (s *Service) finishLogin(ctx context.Context, masterKey ports.MasterKey, response ports.TokenResponse) (LoginResult, error) {
	defer masterKey.Close()
	userKey, err := s.crypto.UnlockUserKey(ctx, ports.UserKeyInput{MasterKey: masterKey, EncryptedUserKey: response.EncryptedUserKey})
	if err != nil {
		return LoginResult{}, err
	}
	tokens := response.Tokens.Clone()
	if tokens.AccountID == "" {
		tokens.AccountID = response.AccountID
	}
	if err := s.tokens.SaveTokens(ctx, tokens); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{AccountID: tokens.AccountID, UserKey: userKey, Tokens: tokens.Clone()}, nil
}

func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func twoFactorProviders(err error) ([]string, bool) {
	var core *errors.Error
	if !errorsAs(err, &core) || core.Kind != errors.KindTwoFactorRequired {
		return nil, false
	}
	return core.TwoFactorProviders, true
}

func supportedProviders(providers []string) ([]ports.TwoFactorProvider, []string) {
	var supported []ports.TwoFactorProvider
	var unsupported []string
	seen := map[ports.TwoFactorProvider]bool{}
	for _, provider := range providers {
		mapped, ok := mapProvider(provider)
		if !ok {
			unsupported = append(unsupported, provider)
			continue
		}
		if !seen[mapped] {
			seen[mapped] = true
			supported = append(supported, mapped)
		}
	}
	return supported, unsupported
}

func mapProvider(provider string) (ports.TwoFactorProvider, bool) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "0", "authenticator", "totp":
		return ports.TwoFactorProviderAuthenticator, true
	case "1", "email":
		return ports.TwoFactorProviderEmail, true
	case "2", "duo":
		return ports.TwoFactorProviderDuo, true
	case "3", "yubikey", "yubi_key":
		return ports.TwoFactorProviderYubiKey, true
	default:
		return "", false
	}
}

func challengeAllows(challenge TwoFactorChallenge, provider ports.TwoFactorProvider) bool {
	for _, allowed := range challenge.Providers {
		if allowed == provider {
			return true
		}
	}
	return false
}

func coreError(kind errors.Kind, op, code, message string) error {
	return &errors.Error{Kind: kind, Op: op, Code: code, Message: message}
}

func errorsAs(err error, target any) bool {
	return stderrors.As(err, target)
}
