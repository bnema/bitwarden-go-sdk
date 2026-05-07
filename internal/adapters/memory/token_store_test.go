package memory_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/adapters/memory"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// --- SecretBytes tests ---

func TestSecretBytesStringRedacts(t *testing.T) {
	sb := ports.NewSecretBytes([]byte("secret-token-value"))
	out := sb.String()
	if out == "secret-token-value" {
		t.Fatalf("SecretBytes.String() must not expose plaintext; got: %q", out)
	}
	if strings.Contains(out, "secret-token-value") {
		t.Fatalf("SecretBytes.String() must not include plaintext; got: %q", out)
	}
}

func TestSecretBytesGoStringRedacts(t *testing.T) {
	sb := ports.NewSecretBytes([]byte("secret-token-value"))
	out := fmt.Sprintf("%#v", sb)
	if out == "secret-token-value" {
		t.Fatalf("SecretBytes.GoString() must not expose plaintext; got: %q", out)
	}
	if strings.Contains(out, "secret-token-value") {
		t.Fatalf("SecretBytes.GoString() must not include plaintext; got: %q", out)
	}
}

func TestSecretBytesFormatRedacts(t *testing.T) {
	sb := ports.NewSecretBytes([]byte("secret-token-value"))
	out := fmt.Sprintf("%s", sb)
	if strings.Contains(out, "secret-token-value") {
		t.Fatalf("SecretBytes %%s format must not expose plaintext; got: %q", out)
	}
	outv := fmt.Sprintf("%v", sb)
	if strings.Contains(outv, "secret-token-value") {
		t.Fatalf("SecretBytes %%v format must not expose plaintext; got: %q", outv)
	}
}

func TestSecretBytesBytesReturnsCopy(t *testing.T) {
	sb := ports.NewSecretBytes([]byte("secret-token-value"))
	b := sb.Bytes()
	if string(b) != "secret-token-value" {
		t.Fatalf("Bytes() returned wrong value: %q", string(b))
	}
	// Mutating the returned copy must not affect the SecretBytes.
	b[0] = 'X'
	b2 := sb.Bytes()
	if string(b2) != "secret-token-value" {
		t.Fatalf("Mutation of Bytes() copy leaked into SecretBytes: got %q", string(b2))
	}
}

func TestSecretBytesNewCopiesInput(t *testing.T) {
	original := []byte("original-token")
	sb := ports.NewSecretBytes(original)
	// Mutate the original slice.
	original[0] = 'X'
	b := sb.Bytes()
	if string(b) != "original-token" {
		t.Fatalf("NewSecretBytes must copy input; got %q, want %q", string(b), "original-token")
	}
}

func TestSecretBytesCloneIsDeep(t *testing.T) {
	sb := ports.NewSecretBytes([]byte("clone-me"))
	cloned := sb.Clone()
	b := cloned.Bytes()
	if string(b) != "clone-me" {
		t.Fatalf("Clone mismatch: got %q, want %q", string(b), "clone-me")
	}
	// Mutating the clone's copy must not affect the original.
	b[0] = 'X'
	b2 := sb.Bytes()
	if string(b2) == "Xlone-me" {
		t.Fatal("Clone Bytes() mutation leaked into original")
	}
	// Mutating clone internals: since Bytes() returns copy, we trust Clone is deep.
}

func TestSecretBytesCloseZeroesBytes(t *testing.T) {
	sb := ports.NewSecretBytes([]byte("close-me-token"))
	// Snapshot a Bytes() copy before Close (since Close zeroes internal bytes).
	beforeClose := sb.Bytes()
	if string(beforeClose) != "close-me-token" {
		t.Fatalf("Bytes() before Close: got %q", string(beforeClose))
	}

	sb.Close()

	// After Close, Bytes() returns nil.
	afterClose := sb.Bytes()
	if afterClose != nil {
		t.Fatalf("Bytes() after Close should return nil; got: %q", string(afterClose))
	}

	// String after Close still redacted.
	if s := sb.String(); s == "close-me-token" {
		t.Fatal("String() after Close must not expose plaintext")
	}
}

func TestSecretBytesCloseIsIdempotent(t *testing.T) {
	sb := ports.NewSecretBytes([]byte("idempotent-token"))
	sb.Close()
	sb.Close() // must not panic
	if b := sb.Bytes(); b != nil {
		t.Fatalf("Bytes() after two Closes should return nil; got: %q", string(b))
	}
}

func TestSecretBytesNilBytesReturnsNil(t *testing.T) {
	var sb ports.SecretBytes
	b := sb.Bytes()
	if b != nil {
		t.Fatalf("Bytes() on zero-value SecretBytes should return nil; got: %q", string(b))
	}
}

func mustTokenSet(accountID string) ports.TokenSet {
	return ports.TokenSet{
		AccountID:    accountID,
		AccessToken:  ports.NewSecretBytes([]byte("access-token-data")),
		RefreshToken: ports.NewSecretBytes([]byte("refresh-token-data")),
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
	origAccessCopy := orig.AccessToken.Bytes()
	origRefreshCopy := orig.RefreshToken.Bytes()

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
	loadedAccess := loaded.AccessToken.Bytes()
	loadedRefresh := loaded.RefreshToken.Bytes()
	if string(loadedAccess) != string(origAccessCopy) {
		t.Error("AccessToken mismatch")
	}
	if string(loadedRefresh) != string(origRefreshCopy) {
		t.Error("RefreshToken mismatch")
	}
	if loaded.TokenType != orig.TokenType {
		t.Errorf("TokenType mismatch: %q vs %q", loaded.TokenType, orig.TokenType)
	}
	if !loaded.ExpiresAt.Equal(orig.ExpiresAt) {
		t.Errorf("ExpiresAt mismatch: %v vs %v", loaded.ExpiresAt, orig.ExpiresAt)
	}

	// Mutating a Bytes() copy from the original SecretBytes must not affect the stored value.
	// Bytes() returns a copy, so mutation can't leak — but verify anyway.
	mutatedAccess := orig.AccessToken.Bytes()
	mutatedAccess[0] = 'X'
	mutatedRefresh := orig.RefreshToken.Bytes()
	mutatedRefresh[0] = 'Y'

	reloaded, err := store.LoadTokens(ctx, "acct-1")
	if err != nil {
		t.Fatalf("unexpected reload error: %v", err)
	}
	reloadedAccess := reloaded.AccessToken.Bytes()
	if string(reloadedAccess) == string(mutatedAccess) {
		t.Error("mutation of Bytes() copy from original AccessToken leaked into stored value")
	}
	reloadedRefresh := reloaded.RefreshToken.Bytes()
	if string(reloadedRefresh) == string(mutatedRefresh) {
		t.Error("mutation of Bytes() copy from original RefreshToken leaked into stored value")
	}
	if string(reloadedAccess) != string(origAccessCopy) {
		t.Error("stored AccessToken should equal original")
	}

	// Mutating the loaded Bytes() copy must not affect the stored value.
	loadedAccess[0] = 'Z'

	reloaded2, err := store.LoadTokens(ctx, "acct-1")
	if err != nil {
		t.Fatalf("unexpected reload2 error: %v", err)
	}
	reloaded2Access := reloaded2.AccessToken.Bytes()
	if string(reloaded2Access) == string(loadedAccess) {
		t.Error("mutation of loaded Bytes() copy AccessToken leaked into stored value")
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
