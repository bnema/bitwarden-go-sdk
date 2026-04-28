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

func TestFoldersListSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	// Login to unlock.
	loginAndUnlock(t, client, identity, crypto, store)

	api.EXPECT().
		ListFolders(mock.Anything).
		Return([]ports.EncryptedFolder{
			{ID: "f1", Name: "enc-banking"},
			{ID: "f2", Name: "enc-work"},
		}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(mock.Anything, mock.Anything, "enc-banking").
		Return("Banking", nil).
		Once()
	crypto.EXPECT().
		DecryptFolderName(mock.Anything, mock.Anything, "enc-work").
		Return("Work", nil).
		Once()

	folders, err := client.Folders().List(context.Background())
	require.NoError(t, err)
	require.Len(t, folders, 2)
	assert.Equal(t, "f1", folders[0].ID)
	assert.Equal(t, "Banking", folders[0].Name)
	assert.Equal(t, "f2", folders[1].ID)
	assert.Equal(t, "Work", folders[1].Name)
}

func TestFoldersCreateSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	loginAndUnlock(t, client, identity, crypto, store)

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, mock.Anything, "Banking").
		Return("enc-banking", nil).
		Once()

	api.EXPECT().
		CreateFolder(mock.Anything, ports.EncryptedFolder{Name: "enc-banking"}).
		Return(ports.EncryptedFolder{ID: "f-new", Name: "enc-banking"}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(mock.Anything, mock.Anything, "enc-banking").
		Return("Banking", nil).
		Once()

	folder, err := client.Folders().Create(context.Background(), "Banking")
	require.NoError(t, err)
	assert.Equal(t, "f-new", folder.ID)
	assert.Equal(t, "Banking", folder.Name)
}

func TestFoldersUpdateSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	loginAndUnlock(t, client, identity, crypto, store)

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, mock.Anything, "Renamed").
		Return("enc-renamed", nil).
		Once()

	api.EXPECT().
		UpdateFolder(mock.Anything, "f1", ports.EncryptedFolder{Name: "enc-renamed"}).
		Return(ports.EncryptedFolder{ID: "f1", Name: "enc-renamed"}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(mock.Anything, mock.Anything, "enc-renamed").
		Return("Renamed", nil).
		Once()

	folder, err := client.Folders().Update(context.Background(), "f1", "Renamed")
	require.NoError(t, err)
	assert.Equal(t, "f1", folder.ID)
	assert.Equal(t, "Renamed", folder.Name)
}

func TestFoldersDeleteSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	loginAndUnlock(t, client, identity, crypto, store)

	api.EXPECT().
		DeleteFolder(mock.Anything, "f1").
		Return(nil).
		Once()

	err = client.Folders().Delete(context.Background(), "f1")
	require.NoError(t, err)
}

func TestFoldersLockedReturnsErrLocked(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)
	require.True(t, client.IsLocked())

	// All folder operations must return ErrLocked without API calls.
	_, err = client.Folders().List(context.Background())
	require.ErrorIs(t, err, ErrLocked)

	_, err = client.Folders().Create(context.Background(), "Test")
	require.ErrorIs(t, err, ErrLocked)

	_, err = client.Folders().Update(context.Background(), "f1", "Test")
	require.ErrorIs(t, err, ErrLocked)

	err = client.Folders().Delete(context.Background(), "f1")
	require.ErrorIs(t, err, ErrLocked)
}

// loginAndUnlock performs a complete 2FA login to unlock the client.
func loginAndUnlock(t testing.TB, client *Client, identity *mocks.MockIdentityClient, crypto *mocks.MockCryptoEngine, store *mocks.MockTokenStore) {
	t.Helper()

	masterKey := ports.MasterKey{Bytes: []byte("master-key-32-bytes-0123456789abcd")}
	userKey := ports.UserKey{Bytes: []byte("user-key-64-bytes-for-testing-purposes-here-1234567890!")}
	tokens := ports.TokenSet{
		AccountID:    "acct-1",
		AccessToken:  ports.NewSecretBytes([]byte("access-token")),
		RefreshToken: ports.NewSecretBytes([]byte("refresh-token")),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").
		Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, mock.Anything).Return(ports.TokenResponse{}, twoFactorCoreError("1"))
	identity.EXPECT().CompleteTwoFactor(mock.Anything, ports.TwoFactorTokenRequest{
		Email: "alice@example.com", AuthHash: "auth-hash",
		Provider: ports.TwoFactorProviderEmail, Code: "123456",
	}).Return(ports.TokenResponse{
		Tokens: tokens, AccountID: "acct-1", EncryptedUserKey: "enc-user-key",
	}, nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, ports.UserKeyInput{
		MasterKey: masterKey, EncryptedUserKey: "enc-user-key",
	}).Return(userKey, nil)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)

	begin, err := client.BeginLogin(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	_, err = client.CompleteLogin(context.Background(), CompleteLoginOptions{
		Challenge: begin.Challenge, Provider: TwoFactorProviderEmail, Code: "123456",
	})
	require.NoError(t, err)
	require.False(t, client.IsLocked())
}
