package ports

import "context"

// IdentityClient defines Bitwarden identity operations used by auth/session core.
type IdentityClient interface {
	Prelogin(ctx context.Context, email string) (PreloginResult, error)
	LoginPassword(ctx context.Context, req PasswordTokenRequest) (TokenResponse, error)
	CompleteTwoFactor(ctx context.Context, req TwoFactorTokenRequest) (TokenResponse, error)
	Refresh(ctx context.Context, req RefreshTokenRequest) (TokenResponse, error)
}

// PreloginResult contains KDF settings returned by the prelogin endpoint.
type PreloginResult struct {
	KDF        KDFConfig
	RegionHint string
}

// PasswordTokenRequest contains form fields for a master-password token request.
type PasswordTokenRequest struct {
	Email            string
	AuthHash         string
	DeviceType       string
	DeviceIdentifier string
	DeviceName       string
}

// TwoFactorTokenRequest continues a password login with a classic 2FA token.
type TwoFactorTokenRequest struct {
	Email            string
	AuthHash         string
	Provider         TwoFactorProvider
	Code             string
	Remember         bool
	DeviceType       string
	DeviceIdentifier string
	DeviceName       string
}

// RefreshTokenRequest contains form fields for OAuth refresh.
type RefreshTokenRequest struct {
	AccountID    string
	ClientID     string
	RefreshToken SecretBytes
}

// TokenResponse contains successful identity token response fields.
type TokenResponse struct {
	Tokens           TokenSet
	AccountID        string
	EncryptedUserKey string
	TokenType        string
	ExpiresInSeconds int
}

// TwoFactorProvider identifies a mapped classic two-factor provider.
type TwoFactorProvider string

const (
	// TwoFactorProviderAuthenticator identifies authenticator-app TOTP.
	TwoFactorProviderAuthenticator TwoFactorProvider = "authenticator"
	// TwoFactorProviderEmail identifies email code 2FA.
	TwoFactorProviderEmail TwoFactorProvider = "email"
	// TwoFactorProviderDuo identifies Duo 2FA.
	TwoFactorProviderDuo TwoFactorProvider = "duo"
	// TwoFactorProviderYubiKey identifies YubiKey OTP 2FA.
	TwoFactorProviderYubiKey TwoFactorProvider = "yubikey"
)

// KDFConfig contains key-derivation settings.
type KDFConfig struct {
	Type        string
	Iterations  int
	MemoryMiB   int
	Parallelism int
}
