package bitwarden

import (
	"context"
	"testing"
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/adapters/memory"
	"github.com/bnema/bitwarden-go-sdk/internal/core/session"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/bnema/bitwarden-go-sdk/internal/testkit/bitwardenremote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestPublicLoginContract verifies the public BeginLogin flow against the
// testkit server without two-factor authentication. It injects a mock crypto
// engine and mock token store while using the real HTTP identity adapter.
func TestPublicLoginContract(t *testing.T) {
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())
	identity := server.NewIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	store := mocks.NewMockTokenStore(t)

	masterKey := ports.MasterKey{Bytes: []byte("deterministic-master-key")}
	userKey := ports.UserKey{Bytes: []byte("deterministic-user-key")}
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("deterministic-auth-hash"), nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, mock.Anything).Return(userKey, nil)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)

	client, err := NewClient(withIdentityClient(identity), withCryptoEngine(crypto), withTokenStore(store))
	require.NoError(t, err)

	result, err := client.BeginLogin(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	assert.NotEmpty(t, result.AccountID)
	assert.Nil(t, result.Challenge)
	assert.False(t, client.IsLocked())

	// Assert recorder saw the expected requests.
	require.NoError(t, server.Recorder().AssertRequest("POST", "/accounts/prelogin/password"))
	require.NoError(t, server.Recorder().AssertRequest("POST", "/connect/token"))

	// Assert no raw bodies or secret values leaked.
	require.NoError(t, server.Recorder().AssertNoRawBodies())
}

// TestPublicTwoFactorLoginContract verifies the public BeginLogin + CompleteLogin
// flow against the testkit server with two-factor authentication enabled (email).
// It injects a mock crypto engine and mock token store while using the real HTTP
// identity adapter.
func TestPublicTwoFactorLoginContract(t *testing.T) {
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario(bitwardenremote.WithTwoFactorProvider("email")))
	identity := server.NewIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	store := mocks.NewMockTokenStore(t)

	masterKey := ports.MasterKey{Bytes: []byte("deterministic-master-key")}
	userKey := ports.UserKey{Bytes: []byte("deterministic-user-key")}
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("deterministic-auth-hash"), nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, mock.Anything).Return(userKey, nil)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)

	client, err := NewClient(withIdentityClient(identity), withCryptoEngine(crypto), withTokenStore(store))
	require.NoError(t, err)

	// BeginLogin should return a two-factor challenge.
	result, err := client.BeginLogin(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	require.NotNil(t, result.Challenge)
	assert.Empty(t, result.AccountID)
	assert.True(t, client.IsLocked())

	// The challenge should list email as a supported provider.
	providers := result.Challenge.Providers()
	assert.Contains(t, providers, TwoFactorProviderEmail)

	// CompleteLogin should succeed with a valid 2FA code.
	complete, err := client.CompleteLogin(context.Background(), CompleteLoginOptions{
		Challenge: result.Challenge,
		Provider:  TwoFactorProviderEmail,
		Code:      "123456",
		Remember:  false,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, complete.AccountID)
	assert.False(t, client.IsLocked())

	// Assert recorder saw all expected requests.
	require.NoError(t, server.Recorder().AssertRequest("POST", "/accounts/prelogin/password"))
	require.NoError(t, server.Recorder().AssertRequest("POST", "/connect/token"))

	// Should have 3 requests: prelogin, token (2FA challenge), token (2FA completion).
	reqs := server.Recorder().Requests()
	assert.Len(t, reqs, 3, "expected prelogin + 2FA challenge + token completion")

	// Assert no raw bodies or secret values leaked.
	require.NoError(t, server.Recorder().AssertNoRawBodies())
}

// TestRefreshContractWithTestkit verifies the token refresh flow against the
// testkit server using the RefreshCoordinator with a real HTTP identity adapter
// and an in-memory token store pre-loaded with an expired refresh token.
func TestRefreshContractWithTestkit(t *testing.T) {
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())
	identity := server.NewIdentityClient(t)

	// Pre-load a memory token store with an expired token set.
	store := memory.NewTokenStore()
	ctx := context.Background()
	err := store.SaveTokens(ctx, ports.TokenSet{
		AccountID:    "account-1",
		AccessToken:  ports.NewSecretBytes([]byte("old-access-token")),
		RefreshToken: ports.NewSecretBytes([]byte("old-refresh-token")),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-time.Hour), // expired
	})
	require.NoError(t, err)

	coord := session.NewRefreshCoordinator(session.RefreshDependencies{
		Identity: identity,
		Tokens:   store,
	})

	refreshed, err := coord.Refresh(ctx, "account-1")
	require.NoError(t, err)
	assert.NotEmpty(t, refreshed.AccessToken.Bytes())
	assert.NotEmpty(t, refreshed.RefreshToken.Bytes())

	// Assert recorder saw /connect/token.
	require.NoError(t, server.Recorder().AssertRequest("POST", "/connect/token"))

	// The recorded KnownFields should include "refresh_token" as a field name
	// (never the value itself).
	reqs := server.Recorder().Requests()
	require.Len(t, reqs, 1, "expected 1 recorded token request")
	assert.Contains(t, reqs[0].KnownFields, "refresh_token",
		"KnownFields should contain field name 'refresh_token'")

	// Ensure no secret values leaked.
	require.NoError(t, server.Recorder().AssertNoRawBodies())
}
