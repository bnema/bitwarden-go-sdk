package ports

import (
	"context"
	"fmt"
	"time"
)

// SecretBytes holds sensitive bytes with redacted String/GoString and zero-on-Close semantics.
type SecretBytes struct {
	buf []byte
}

const secretBytesRedacted = "[REDACTED_SECRET_BYTES]"

// NewSecretBytes returns a SecretBytes holding a copy of value.
func NewSecretBytes(value []byte) SecretBytes {
	buf := make([]byte, len(value))
	copy(buf, value)
	return SecretBytes{buf: buf}
}

// Bytes returns a copy of the held bytes.
func (s SecretBytes) Bytes() []byte {
	if s.buf == nil {
		return nil
	}
	cpy := make([]byte, len(s.buf))
	copy(cpy, s.buf)
	return cpy
}

// String returns a constant redacted text. It never includes plaintext.
func (s SecretBytes) String() string {
	return secretBytesRedacted
}

// GoString returns a constant redacted text for %#v formatting.
func (s SecretBytes) GoString() string {
	return secretBytesRedacted
}

// Clone returns a deep copy of the SecretBytes.
func (s SecretBytes) Clone() SecretBytes {
	return NewSecretBytes(s.buf)
}

// Close zeros the internal bytes and releases the buffer. It is idempotent.
func (s *SecretBytes) Close() {
	for i := range s.buf {
		s.buf[i] = 0
	}
	s.buf = nil
}

// Format implements fmt.Formatter to prevent %s/%v exposure.
func (s SecretBytes) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(secretBytesRedacted))
}

// TokenSet holds OAuth token fields for a single account.
type TokenSet struct {
	AccountID    string
	AccessToken  SecretBytes
	RefreshToken SecretBytes
	TokenType    string
	ExpiresAt    time.Time
}

// Clone returns a deep copy of the TokenSet so that stores can avoid
// aliasing internal byte slices.
func (t TokenSet) Clone() TokenSet {
	c := t
	c.AccessToken = t.AccessToken.Clone()
	c.RefreshToken = t.RefreshToken.Clone()
	return c
}

// Close zeros sensitive token bytes. It is idempotent.
func (t *TokenSet) Close() {
	t.AccessToken.Close()
	t.RefreshToken.Close()
}

// TokenStore persists token sets keyed by account.
type TokenStore interface {
	LoadTokens(ctx context.Context, accountID string) (TokenSet, error)
	SaveTokens(ctx context.Context, tokens TokenSet) error
	DeleteTokens(ctx context.Context, accountID string) error
}
