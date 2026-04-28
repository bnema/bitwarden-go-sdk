package memory

import (
	"context"
	"sync"

	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// TokenStore is a mutex-protected in-memory implementation of ports.TokenStore.
type TokenStore struct {
	mu   sync.RWMutex
	data map[string]ports.TokenSet
}

// NewTokenStore returns an empty, ready-to-use *TokenStore.
func NewTokenStore() *TokenStore {
	return &TokenStore{
		data: make(map[string]ports.TokenSet),
	}
}

// LoadTokens returns the token set for the given account ID, or an error if not found.
func (s *TokenStore) LoadTokens(ctx context.Context, accountID string) (ports.TokenSet, error) {
	if err := ctx.Err(); err != nil {
		return ports.TokenSet{}, err
	}

	s.mu.RLock()
	ts, ok := s.data[accountID]
	if ok {
		ts = ts.Clone()
	}
	s.mu.RUnlock()

	if !ok {
		return ports.TokenSet{}, &coreerrors.Error{
			Kind:    coreerrors.KindNotFound,
			Op:      "TokenStore.LoadTokens",
			Message: "tokens not found for account",
		}
	}
	return ts, nil
}

// SaveTokens stores the given token set, replacing any existing entry for the same account.
func (s *TokenStore) SaveTokens(ctx context.Context, tokens ports.TokenSet) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if tokens.AccountID == "" {
		return &coreerrors.Error{
			Kind:    coreerrors.KindValidation,
			Op:      "TokenStore.SaveTokens",
			Message: "AccountID must not be empty",
		}
	}

	cloned := tokens.Clone()

	s.mu.Lock()
	if existing, ok := s.data[tokens.AccountID]; ok {
		existing.Close()
	}
	s.data[tokens.AccountID] = cloned
	s.mu.Unlock()

	return nil
}

// DeleteTokens removes the token set for the given account ID. It is idempotent.
func (s *TokenStore) DeleteTokens(ctx context.Context, accountID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	if existing, ok := s.data[accountID]; ok {
		existing.Close()
		delete(s.data, accountID)
	}
	s.mu.Unlock()

	return nil
}
