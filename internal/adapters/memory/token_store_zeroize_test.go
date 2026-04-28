package memory

import (
	"context"
	"testing"
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

func tokenSetForZeroizeTest(accountID, access, refresh string) ports.TokenSet {
	return ports.TokenSet{
		AccountID:    accountID,
		AccessToken:  ports.NewSecretBytes([]byte(access)),
		RefreshToken: ports.NewSecretBytes([]byte(refresh)),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
}

func allZero(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestTokenStore_SaveTokensZeroesReplacedTokens(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	oldTokens := tokenSetForZeroizeTest("acct-1", "old-access-token", "old-refresh-token")
	if err := store.SaveTokens(ctx, oldTokens); err != nil {
		t.Fatalf("save old tokens: %v", err)
	}

	store.mu.RLock()
	storedOld := store.data["acct-1"]
	store.mu.RUnlock()
	if string(storedOld.AccessToken.Bytes()) != "old-access-token" {
		t.Fatal("test setup failed: old access token not stored")
	}

	newTokens := tokenSetForZeroizeTest("acct-1", "new-access-token", "new-refresh-token")
	if err := store.SaveTokens(ctx, newTokens); err != nil {
		t.Fatalf("save replacement tokens: %v", err)
	}

	if !allZero(storedOld.AccessToken.Bytes()) {
		t.Fatalf("replaced access token bytes were not zeroed: %v", storedOld.AccessToken.Bytes())
	}
	if !allZero(storedOld.RefreshToken.Bytes()) {
		t.Fatalf("replaced refresh token bytes were not zeroed: %v", storedOld.RefreshToken.Bytes())
	}
}

func TestTokenStore_DeleteTokensZeroesDeletedTokens(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	tokens := tokenSetForZeroizeTest("acct-1", "delete-access-token", "delete-refresh-token")
	if err := store.SaveTokens(ctx, tokens); err != nil {
		t.Fatalf("save tokens: %v", err)
	}

	store.mu.RLock()
	stored := store.data["acct-1"]
	store.mu.RUnlock()
	if string(stored.RefreshToken.Bytes()) != "delete-refresh-token" {
		t.Fatal("test setup failed: refresh token not stored")
	}

	if err := store.DeleteTokens(ctx, "acct-1"); err != nil {
		t.Fatalf("delete tokens: %v", err)
	}

	if !allZero(stored.AccessToken.Bytes()) {
		t.Fatalf("deleted access token bytes were not zeroed: %v", stored.AccessToken.Bytes())
	}
	if !allZero(stored.RefreshToken.Bytes()) {
		t.Fatalf("deleted refresh token bytes were not zeroed: %v", stored.RefreshToken.Bytes())
	}
}
