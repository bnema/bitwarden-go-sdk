package bitwarden

import (
	"context"

	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// TokenStore persists token sets keyed by account.
// Implementations must deep-copy tokens on save and return deep copies on load.
// Sensitive token bytes should be zeroized on Close or when replaced.
type TokenStore interface {
	// SaveTokens stores the given token set, replacing any existing entry for
	// the same account.
	SaveTokens(ctx context.Context, tokens TokenSet) error

	// LoadTokens retrieves the token set for the given account ID.
	LoadTokens(ctx context.Context, accountID string) (TokenSet, error)

	// DeleteTokens removes the token set for the given account ID.
	DeleteTokens(ctx context.Context, accountID string) error
}

// tokenStoreAdapter adapts a public TokenStore to the internal ports.TokenStore
// interface, converting between public and internal token set types.
type tokenStoreAdapter struct {
	pub TokenStore
}

func (a *tokenStoreAdapter) SaveTokens(ctx context.Context, tokens ports.TokenSet) error {
	return a.pub.SaveTokens(ctx, tokenSetFromPorts(tokens))
}

func (a *tokenStoreAdapter) LoadTokens(ctx context.Context, accountID string) (ports.TokenSet, error) {
	pub, err := a.pub.LoadTokens(ctx, accountID)
	if err != nil {
		return ports.TokenSet{}, err
	}
	return tokenSetToPorts(pub), nil
}

func (a *tokenStoreAdapter) DeleteTokens(ctx context.Context, accountID string) error {
	return a.pub.DeleteTokens(ctx, accountID)
}

// tokenSetToPorts converts a public TokenSet to an internal ports.TokenSet,
// deep-copying sensitive byte slices.
func tokenSetToPorts(pub TokenSet) ports.TokenSet {
	return ports.TokenSet{
		AccountID:    pub.AccountID,
		AccessToken:  ports.NewSecretBytes(pub.AccessToken),
		RefreshToken: ports.NewSecretBytes(pub.RefreshToken),
		TokenType:    pub.TokenType,
		ExpiresAt:    pub.ExpiresAt,
	}
}

// tokenSetFromPorts converts an internal ports.TokenSet to a public TokenSet,
// deep-copying sensitive byte slices.
func tokenSetFromPorts(in ports.TokenSet) TokenSet {
	return TokenSet{
		AccountID:    in.AccountID,
		AccessToken:  in.AccessToken.Bytes(),
		RefreshToken: in.RefreshToken.Bytes(),
		TokenType:    in.TokenType,
		ExpiresAt:    in.ExpiresAt,
	}
}
