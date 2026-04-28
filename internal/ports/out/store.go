package out

import "context"

// TokenStore persists scaffold token sets.
type TokenStore interface {
	LoadTokens(ctx context.Context) (TokenSet, error)
	SaveTokens(ctx context.Context, tokens TokenSet) error
	ClearTokens(ctx context.Context) error
}
