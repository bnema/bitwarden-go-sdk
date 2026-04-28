package ports

import (
	"context"
	"time"
)

// TokenSet holds OAuth token fields for a single account.
// AccessToken and RefreshToken are stored as []byte to avoid accidental
// string copies into logs or debug output.
type TokenSet struct {
	AccountID    string
	AccessToken  []byte
	RefreshToken []byte
	TokenType    string
	ExpiresAt    time.Time
}

// Clone returns a deep copy of the TokenSet so that stores can avoid
// aliasing internal byte slices.
func (t TokenSet) Clone() TokenSet {
	c := t
	if t.AccessToken != nil {
		c.AccessToken = make([]byte, len(t.AccessToken))
		copy(c.AccessToken, t.AccessToken)
	}
	if t.RefreshToken != nil {
		c.RefreshToken = make([]byte, len(t.RefreshToken))
		copy(c.RefreshToken, t.RefreshToken)
	}
	return c
}

// TokenStore persists token sets keyed by account.
type TokenStore interface {
	LoadTokens(ctx context.Context, accountID string) (TokenSet, error)
	SaveTokens(ctx context.Context, tokens TokenSet) error
	DeleteTokens(ctx context.Context, accountID string) error
}
