package out

import "context"

// Types in this package are compile-safe scaffold contracts. The source-mapping
// plan must verify and adjust field names before real Bitwarden behavior is added.
type IdentityClient interface {
	Prelogin(ctx context.Context, email string) (PreloginResult, error)
	LoginPassword(ctx context.Context, req LoginRequest) (LoginResult, error)
	Refresh(ctx context.Context, refreshToken string) (TokenSet, error)
}

type PreloginResult struct {
	KDF        KDFConfig
	RegionHint string
}

type LoginRequest struct {
	Email     string
	AuthHash  string
	TwoFactor *TwoFactorRequest
}

type TwoFactorRequest struct {
	Provider string
	Code     string
}

type LoginResult struct {
	Tokens TokenSet
	UserID string
}

type TokenSet struct {
	AccessToken  string
	RefreshToken string
	ExpiresInSec int
}

type KDFConfig struct {
	Type        string
	Iterations  int
	MemoryMiB   int
	Parallelism int
}
