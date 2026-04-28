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
