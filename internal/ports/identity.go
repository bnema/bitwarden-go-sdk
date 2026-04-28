package ports

import "context"

// IdentityClient defines scaffold Bitwarden identity operations.
// Types in this package are compile-safe scaffold contracts. The source-mapping
// plan must verify and adjust field names before real Bitwarden behavior is added.
type IdentityClient interface {
	Prelogin(ctx context.Context, email string) (PreloginResult, error)
	LoginPassword(ctx context.Context, req LoginRequest) (LoginResult, error)
	Refresh(ctx context.Context, refreshToken string) (TokenSet, error)
}

// PreloginResult contains scaffold prelogin response fields.
type PreloginResult struct {
	KDF        KDFConfig
	RegionHint string
}

// LoginRequest contains scaffold login request fields.
type LoginRequest struct {
	Email     string
	AuthHash  string
	TwoFactor *TwoFactorRequest
}

// TwoFactorRequest contains scaffold two-factor request fields.
type TwoFactorRequest struct {
	Provider string
	Code     string
}

// LoginResult contains scaffold login response fields.
type LoginResult struct {
	Tokens TokenSet
	UserID string
}

// KDFConfig contains scaffold key-derivation settings.
type KDFConfig struct {
	Type        string
	Iterations  int
	MemoryMiB   int
	Parallelism int
}
