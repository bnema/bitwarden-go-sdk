package bitwarden

import (
	"context"
	"testing"
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestLockClearsKeyAndLockedOperationsFail(t *testing.T) {
	client := loggedInClientForSessionTests(t, nil)
	require.False(t, client.IsLocked())

	client.Lock()
	assert.True(t, client.IsLocked())
	assert.Nil(t, client.userKey.Bytes)

	_, err := client.Vault().Search(context.Background(), "anything")
	require.ErrorIs(t, err, ErrLocked)
}

func TestLogoutClearsTokensAndLocks(t *testing.T) {
	store := mocks.NewMockTokenStore(t)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)
	store.EXPECT().DeleteTokens(mock.Anything, "account-logout").Return(nil)
	client := loggedInClientForSessionTests(t, store)
	client.accountID = "account-logout"

	err := client.Logout(context.Background())
	require.NoError(t, err)
	assert.True(t, client.IsLocked())
	assert.Empty(t, client.accountID)
	assert.Nil(t, client.userKey.Bytes)
}

func TestSessionMaterialCloneDoesNotShareSecretSlices(t *testing.T) {
	original := SessionMaterial{
		AccountID: "acct-1",
		UserKey:   []byte("user-key"),
		Tokens: TokenSet{
			AccountID:    "acct-1",
			AccessToken:  []byte("access"),
			RefreshToken: []byte("refresh"),
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
		},
	}
	clone := original.Clone()

	// Mutate original slices
	original.UserKey[0] = 'X'
	original.Tokens.AccessToken[0] = 'Y'
	original.Tokens.RefreshToken[0] = 'Z'

	assert.Equal(t, []byte("user-key"), clone.UserKey)
	assert.Equal(t, []byte("access"), clone.Tokens.AccessToken)
	assert.Equal(t, []byte("refresh"), clone.Tokens.RefreshToken)
	assert.Equal(t, "acct-1", clone.AccountID)
	assert.Equal(t, "acct-1", clone.Tokens.AccountID)
	assert.Equal(t, "Bearer", clone.Tokens.TokenType)
}

func TestSessionMaterialCloseZeroesSecrets(t *testing.T) {
	// Arrange: capture backing arrays
	userKey := []byte("user-key")
	accessToken := []byte("access")
	refreshToken := []byte("refresh")

	mat := SessionMaterial{
		AccountID: "acct-1",
		UserKey:   userKey,
		Tokens: TokenSet{
			AccountID:    "acct-1",
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
		},
	}

	mat.Close()

	assertAllZeroed(t, userKey)
	assertAllZeroed(t, accessToken)
	assertAllZeroed(t, refreshToken)
	assert.Nil(t, mat.UserKey)
	assert.Nil(t, mat.Tokens.AccessToken)
	assert.Nil(t, mat.Tokens.RefreshToken)
}

func assertAllZeroed(t *testing.T, b []byte) {
	t.Helper()
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte at index %d is %d, expected 0", i, v)
		}
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	client := loggedInClientForSessionTests(t, nil)

	require.NoError(t, client.Close())
	require.NoError(t, client.Close())
	assert.True(t, client.IsLocked())
	assert.Nil(t, client.userKey.Bytes)
}

func loggedInClientForSessionTests(t *testing.T, store ports.TokenStore) *Client {
	t.Helper()
	identity := mocks.NewMockIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	if store == nil {
		mockStore := mocks.NewMockTokenStore(t)
		mockStore.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)
		store = mockStore
	}
	masterKey := ports.MasterKey{Bytes: []byte("master")}
	userKey := ports.UserKey{Bytes: []byte("user")}
	tokens := ports.TokenSet{AccountID: "account-1", AccessToken: ports.NewSecretBytes([]byte("access")), RefreshToken: ports.NewSecretBytes([]byte("refresh")), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}
	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, mock.Anything).Return(ports.TokenResponse{Tokens: tokens, AccountID: "account-1", EncryptedUserKey: "enc-user"}, nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, ports.UserKeyInput{MasterKey: masterKey, EncryptedUserKey: "enc-user"}).Return(userKey, nil)
	client, err := NewClient(withIdentityClient(identity), withCryptoEngine(crypto), withTokenStore(store))
	require.NoError(t, err)
	_, err = client.BeginLogin(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	return client
}
