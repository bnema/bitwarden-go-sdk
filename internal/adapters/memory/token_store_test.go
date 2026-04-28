package memory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/adapters/memory"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

func mustTokenSet(accountID string) ports.TokenSet {
	return ports.TokenSet{
		AccountID:    accountID,
		AccessToken:  []byte("access-token-data"),
		RefreshToken: []byte("refresh-token-data"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
}

func TestTokenStore_LoadMissingReturnsNotFound(t *testing.T) {
	store := memory.NewTokenStore()
	ctx := context.Background()

	_, err := store.LoadTokens(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error loading missing account")
	}
	if !coreerrors.Is(err, coreerrors.KindNotFound) {
		t.Fatalf("expected KindNotFound error, got: %v", err)
	}
}

func TestTokenStore_SaveThenLoadReturnsCopy(t *testing.T) {
	store := memory.NewTokenStore()
	ctx := context.Background()

	orig := mustTokenSet("acct-1")

	err := store.SaveTokens(ctx, orig)
	if err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	loaded, err := store.LoadTokens(ctx, "acct-1")
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	// Loaded tokens should equal originals in value.
	if loaded.AccountID != orig.AccountID {
		t.Errorf("AccountID mismatch: %q vs %q", loaded.AccountID, orig.AccountID)
	}
	if string(loaded.AccessToken) != string(orig.AccessToken) {
		t.Error("AccessToken mismatch")
	}
	if string(loaded.RefreshToken) != string(orig.RefreshToken) {
		t.Error("RefreshToken mismatch")
	}
	if loaded.TokenType != orig.TokenType {
		t.Errorf("TokenType mismatch: %q vs %q", loaded.TokenType, orig.TokenType)
	}
	if !loaded.ExpiresAt.Equal(orig.ExpiresAt) {
		t.Errorf("ExpiresAt mismatch: %v vs %v", loaded.ExpiresAt, orig.ExpiresAt)
	}

	// Mutating the original must not affect the stored value.
	orig.AccessToken[0] = 'X'
	orig.RefreshToken[0] = 'Y'

	reloaded, err := store.LoadTokens(ctx, "acct-1")
	if err != nil {
		t.Fatalf("unexpected reload error: %v", err)
	}
	if string(reloaded.AccessToken) == string(orig.AccessToken) {
		t.Error("mutation of original AccessToken leaked into stored value")
	}
	if string(reloaded.RefreshToken) == string(orig.RefreshToken) {
		t.Error("mutation of original RefreshToken leaked into stored value")
	}

	// Mutating the loaded tokens must not affect the stored value.
	loaded.AccessToken[0] = 'Z'

	reloaded2, err := store.LoadTokens(ctx, "acct-1")
	if err != nil {
		t.Fatalf("unexpected reload2 error: %v", err)
	}
	if string(reloaded2.AccessToken) == string(loaded.AccessToken) {
		t.Error("mutation of loaded AccessToken leaked into stored value")
	}
}

func TestTokenStore_DeleteRemovesTokens(t *testing.T) {
	store := memory.NewTokenStore()
	ctx := context.Background()

	err := store.SaveTokens(ctx, mustTokenSet("acct-1"))
	if err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	// Delete must succeed.
	err = store.DeleteTokens(ctx, "acct-1")
	if err != nil {
		t.Fatalf("unexpected delete error: %v", err)
	}

	// Load after delete must return not-found.
	_, err = store.LoadTokens(ctx, "acct-1")
	if err == nil {
		t.Fatal("expected error after delete")
	}
	if !coreerrors.Is(err, coreerrors.KindNotFound) {
		t.Fatalf("expected KindNotFound after delete, got: %v", err)
	}

	// Delete of missing must succeed (idempotent).
	err = store.DeleteTokens(ctx, "acct-1")
	if err != nil {
		t.Fatalf("delete of missing should be nil, got: %v", err)
	}
}

func TestTokenStore_SaveRejectsEmptyAccountID(t *testing.T) {
	store := memory.NewTokenStore()
	ctx := context.Background()

	tokens := mustTokenSet("")
	tokens.AccountID = ""

	err := store.SaveTokens(ctx, tokens)
	if err == nil {
		t.Fatal("expected validation error for empty AccountID")
	}
	if !coreerrors.Is(err, coreerrors.KindValidation) {
		t.Fatalf("expected KindValidation error, got: %v", err)
	}
}

func TestTokenStore_AlreadyCancelledContextReturnsError(t *testing.T) {
	store := memory.NewTokenStore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// All three methods should return context error when ctx is already cancelled.
	_, err := store.LoadTokens(ctx, "acct-1")
	if err == nil || err.Error() != context.Canceled.Error() {
		t.Fatalf("LoadTokens with cancelled ctx: got %v, want context.Canceled", err)
	}

	err = store.SaveTokens(ctx, mustTokenSet("acct-1"))
	if err == nil || err.Error() != context.Canceled.Error() {
		t.Fatalf("SaveTokens with cancelled ctx: got %v, want context.Canceled", err)
	}

	err = store.DeleteTokens(ctx, "acct-1")
	if err == nil || err.Error() != context.Canceled.Error() {
		t.Fatalf("DeleteTokens with cancelled ctx: got %v, want context.Canceled", err)
	}
}

func TestTokenStore_ConcurrentAccess(t *testing.T) {
	store := memory.NewTokenStore()
	ctx := context.Background()

	err := store.SaveTokens(ctx, mustTokenSet("acct-1"))
	if err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	var wg sync.WaitGroup
	const goroutines = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(_ int) {
			defer wg.Done()

			// Mix of loads and saves on the same account.
			_, _ = store.LoadTokens(ctx, "acct-1")

			ts := mustTokenSet("acct-1")
			_ = store.SaveTokens(ctx, ts)
		}(i)
	}

	wg.Wait()

	// Should still be loadable after concurrent access.
	_, err = store.LoadTokens(ctx, "acct-1")
	if err != nil {
		t.Fatalf("load after concurrent access failed: %v", err)
	}
}
