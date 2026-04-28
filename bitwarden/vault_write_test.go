package bitwarden

import (
	"context"
	"testing"
	"time"

	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/core/vault"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Vault.Create
// ---------------------------------------------------------------------------

func TestVaultCreateEncryptsAndUpdatesList(t *testing.T) {
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

	// Create an item with a Password secret.
	item := Item{
		Type:     ItemTypeLogin,
		Name:     "New Login",
		Username: "alice",
		Password: NewSecretString("p@ssw0rd"),
		URI:      "https://example.com",
	}

	// EncryptCipher mock expectations.
	encrypted := ports.EncryptedCipher{
		Type: vault.TypeLogin,
		Name: "enc-name",
		Login: &ports.EncryptedLoginCipher{
			Username: "enc-user",
			Password: "enc-pass",
		},
	}

	returned := ports.EncryptedCipher{
		ID:   "c-new",
		Type: vault.TypeLogin,
		Name: "enc-name",
		Login: &ports.EncryptedLoginCipher{
			Username: "enc-user",
			Password: "enc-pass",
		},
	}

	decrypted := ports.Cipher{
		ID:   "c-new",
		Type: vault.TypeLogin,
		Name: "New Login",
		Login: &ports.LoginCipher{
			Username: "alice",
			Password: "p@ssw0rd",
		},
	}

	crypto.EXPECT().
		EncryptCipher(mock.Anything, userKey, mock.MatchedBy(func(c ports.Cipher) bool {
			return c.Type == vault.TypeLogin && c.Name == "New Login" &&
				c.Login != nil && c.Login.Username == "alice" && c.Login.Password == "p@ssw0rd"
		})).
		Return(encrypted, nil).
		Once()

	api.EXPECT().
		CreateCipher(mock.Anything, encrypted).
		Return(returned, nil).
		Once()

	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, returned).
		Return(decrypted, nil).
		Once()

	created, err := client.Vault().Create(context.Background(), item)
	require.NoError(t, err)
	assert.Equal(t, ItemID("c-new"), created.ID)
	assert.Equal(t, "New Login", created.Name)
	assert.Equal(t, "alice", created.Username)

	// Password is *Secret — must not be exposed as plaintext.
	require.NotNil(t, created.Password)
	assert.Equal(t, "[REDACTED]", created.Password.String())

	// List must include the new item.
	items, err := client.Vault().List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, ItemID("c-new"), items[0].ID)
}

func TestVaultCreateWithPasswordSecretDoesNotExposeViaFmtSprint(t *testing.T) {
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

	// Quick login to unlock.
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

	item := Item{
		Type:     ItemTypeLogin,
		Name:     "Secret Test",
		Username: "alice",
		Password: NewSecretString("super-secret-password-123"),
	}

	// Set up mocks for a successful create.
	encrypted := ports.EncryptedCipher{
		Type: vault.TypeLogin,
		Name: "enc-name",
		Login: &ports.EncryptedLoginCipher{
			Username: "enc-user",
			Password: "enc-pass",
		},
	}
	returned := ports.EncryptedCipher{
		ID:   "c-sec",
		Type: vault.TypeLogin,
		Name: "enc-name",
		Login: &ports.EncryptedLoginCipher{
			Username: "enc-user",
			Password: "enc-pass",
		},
	}
	decrypted := ports.Cipher{
		ID:   "c-sec",
		Type: vault.TypeLogin,
		Name: "Secret Test",
		Login: &ports.LoginCipher{
			Username: "alice",
			Password: "super-secret-password-123",
		},
	}

	crypto.EXPECT().
		EncryptCipher(mock.Anything, userKey, mock.Anything).
		Return(encrypted, nil).
		Once()
	api.EXPECT().
		CreateCipher(mock.Anything, encrypted).
		Return(returned, nil).
		Once()
	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, returned).
		Return(decrypted, nil).
		Once()

	created, err := client.Vault().Create(context.Background(), item)
	require.NoError(t, err)

	// The Password field must be redacted in String() output — this simulates
	// accidentally printing the struct. If the secret leaks, this assertion
	// will fail as a safety net.
	str := created.Password.String()
	assert.Equal(t, "[REDACTED]", str, "Password must not be exposed via String()")
}

// ---------------------------------------------------------------------------
// Vault.Update
// ---------------------------------------------------------------------------

func TestVaultUpdateEncryptsAndUpdatesList(t *testing.T) {
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

	// Pre-populate with sync.
	api.EXPECT().
		Sync(mock.Anything, ports.SyncOptions{}).
		Return(ports.SyncResult{
			Ciphers: []ports.EncryptedCipher{
				{ID: "c1", Type: vault.TypeLogin, Name: "enc-old"},
			},
		}, nil).
		Once()
	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, ports.EncryptedCipher{ID: "c1", Type: vault.TypeLogin, Name: "enc-old"}).
		Return(ports.Cipher{ID: "c1", Type: vault.TypeLogin, Name: "Old Login"}, nil).
		Once()

	err = client.Sync(context.Background())
	require.NoError(t, err)

	// Update the item.
	update := Item{
		Type:     ItemTypeLogin,
		Name:     "Updated Login",
		Username: "alice_updated",
	}

	encrypted := ports.EncryptedCipher{
		Type: vault.TypeLogin,
		Name: "enc-updated",
		Login: &ports.EncryptedLoginCipher{
			Username: "enc-user-updated",
		},
	}
	returned := ports.EncryptedCipher{
		ID:   "c1",
		Type: vault.TypeLogin,
		Name: "enc-updated",
		Login: &ports.EncryptedLoginCipher{
			Username: "enc-user-updated",
		},
	}
	decrypted := ports.Cipher{
		ID:   "c1",
		Type: vault.TypeLogin,
		Name: "Updated Login",
		Login: &ports.LoginCipher{
			Username: "alice_updated",
		},
	}

	crypto.EXPECT().
		EncryptCipher(mock.Anything, userKey, mock.MatchedBy(func(c ports.Cipher) bool {
			return c.Type == vault.TypeLogin && c.Name == "Updated Login"
		})).
		Return(encrypted, nil).
		Once()
	api.EXPECT().
		UpdateCipher(mock.Anything, "c1", encrypted).
		Return(returned, nil).
		Once()
	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, returned).
		Return(decrypted, nil).
		Once()

	updated, err := client.Vault().Update(context.Background(), "c1", update)
	require.NoError(t, err)
	assert.Equal(t, ItemID("c1"), updated.ID)
	assert.Equal(t, "Updated Login", updated.Name)
	assert.Equal(t, "alice_updated", updated.Username)

	// List must reflect the update.
	items, err := client.Vault().List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "Updated Login", items[0].Name)
}

// ---------------------------------------------------------------------------
// Vault.Trash
// ---------------------------------------------------------------------------

func TestVaultTrashRemovesFromList(t *testing.T) {
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

	// Pre-populate with sync returning two items.
	api.EXPECT().
		Sync(mock.Anything, ports.SyncOptions{}).
		Return(ports.SyncResult{
			Ciphers: []ports.EncryptedCipher{
				{ID: "c1", Type: vault.TypeLogin, Name: "enc-one"},
				{ID: "c2", Type: vault.TypeLogin, Name: "enc-two"},
			},
		}, nil).
		Once()
	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, ports.EncryptedCipher{ID: "c1", Type: vault.TypeLogin, Name: "enc-one"}).
		Return(ports.Cipher{ID: "c1", Type: vault.TypeLogin, Name: "Item One"}, nil).
		Once()
	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, ports.EncryptedCipher{ID: "c2", Type: vault.TypeLogin, Name: "enc-two"}).
		Return(ports.Cipher{ID: "c2", Type: vault.TypeLogin, Name: "Item Two"}, nil).
		Once()

	err = client.Sync(context.Background())
	require.NoError(t, err)

	// Trash c1.
	api.EXPECT().
		TrashCipher(mock.Anything, "c1").
		Return(nil).
		Once()

	err = client.Vault().Trash(context.Background(), "c1")
	require.NoError(t, err)

	// List must have only c2.
	items, err := client.Vault().List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, ItemID("c2"), items[0].ID)
}

// ---------------------------------------------------------------------------
// Vault.Restore
// ---------------------------------------------------------------------------

func TestVaultRestoreUpsertsList(t *testing.T) {
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

	// Pre-populate with sync containing c2 only.
	api.EXPECT().
		Sync(mock.Anything, ports.SyncOptions{}).
		Return(ports.SyncResult{
			Ciphers: []ports.EncryptedCipher{
				{ID: "c2", Type: vault.TypeLogin, Name: "enc-two"},
			},
		}, nil).
		Once()
	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, ports.EncryptedCipher{ID: "c2", Type: vault.TypeLogin, Name: "enc-two"}).
		Return(ports.Cipher{ID: "c2", Type: vault.TypeLogin, Name: "Item Two"}, nil).
		Once()

	err = client.Sync(context.Background())
	require.NoError(t, err)

	// Restore c1.
	returned := ports.EncryptedCipher{
		ID:   "c1",
		Type: vault.TypeLogin,
		Name: "enc-restored",
	}
	decrypted := ports.Cipher{
		ID:   "c1",
		Type: vault.TypeLogin,
		Name: "Restored Login",
	}

	api.EXPECT().
		RestoreCipher(mock.Anything, "c1").
		Return(returned, nil).
		Once()
	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, returned).
		Return(decrypted, nil).
		Once()

	restored, err := client.Vault().Restore(context.Background(), "c1")
	require.NoError(t, err)
	assert.Equal(t, ItemID("c1"), restored.ID)
	assert.Equal(t, "Restored Login", restored.Name)

	// List must have both items.
	items, err := client.Vault().List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 2)
}

// ---------------------------------------------------------------------------
// Vault.Delete
// ---------------------------------------------------------------------------

func TestVaultDeleteRemovesFromList(t *testing.T) {
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

	// Pre-populate with sync returning two items.
	api.EXPECT().
		Sync(mock.Anything, ports.SyncOptions{}).
		Return(ports.SyncResult{
			Ciphers: []ports.EncryptedCipher{
				{ID: "c1", Type: vault.TypeLogin, Name: "enc-one"},
				{ID: "c2", Type: vault.TypeLogin, Name: "enc-two"},
			},
		}, nil).
		Once()
	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, ports.EncryptedCipher{ID: "c1", Type: vault.TypeLogin, Name: "enc-one"}).
		Return(ports.Cipher{ID: "c1", Type: vault.TypeLogin, Name: "Item One"}, nil).
		Once()
	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, ports.EncryptedCipher{ID: "c2", Type: vault.TypeLogin, Name: "enc-two"}).
		Return(ports.Cipher{ID: "c2", Type: vault.TypeLogin, Name: "Item Two"}, nil).
		Once()

	err = client.Sync(context.Background())
	require.NoError(t, err)

	// Delete c1.
	api.EXPECT().
		DeleteCipher(mock.Anything, "c1").
		Return(nil).
		Once()

	err = client.Vault().Delete(context.Background(), "c1")
	require.NoError(t, err)

	// List must have only c2.
	items, err := client.Vault().List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, ItemID("c2"), items[0].ID)
}

// ---------------------------------------------------------------------------
// Locked guard for all write operations
// ---------------------------------------------------------------------------

func TestVaultWritesLockedReturnErrLocked(t *testing.T) {
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

	// Login and then lock.
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

	// Lock the client.
	client.Lock()
	require.True(t, client.IsLocked())

	ctx := context.Background()

	_, err = client.Vault().Create(ctx, Item{})
	require.ErrorIs(t, err, ErrLocked)

	_, err = client.Vault().Update(ctx, "id", Item{})
	require.ErrorIs(t, err, ErrLocked)

	err = client.Vault().Trash(ctx, "id")
	require.ErrorIs(t, err, ErrLocked)

	_, err = client.Vault().Restore(ctx, "id")
	require.ErrorIs(t, err, ErrLocked)

	err = client.Vault().Delete(ctx, "id")
	require.ErrorIs(t, err, ErrLocked)
}

func TestVaultCreateLockedBeforeLogin(t *testing.T) {
	client, err := NewClient(WithAPIClient(mocks.NewMockAPIClient(t)))
	require.NoError(t, err)
	require.True(t, client.IsLocked())

	_, err = client.Vault().Create(context.Background(), Item{})
	require.ErrorIs(t, err, ErrLocked)
}

// ---------------------------------------------------------------------------
// itemToCore nil card/identity guards
// ---------------------------------------------------------------------------

func TestVaultCreateNilCardReturnsValidationError(t *testing.T) {
	client, err := NewClient(WithAPIClient(mocks.NewMockAPIClient(t)))
	require.NoError(t, err)

	// Create an Item with TypeCard but nil Card — should not panic.
	item := Item{
		Type: ItemTypeCard,
		Name: "Card Without Fields",
	}

	_, err = client.itemToCore(item)
	require.Error(t, err)

	// itemToCore returns *coreerrors.Error with KindValidation.
	require.True(t, coreerrors.Is(err, coreerrors.KindValidation),
		"expected validation-kind error, got %T: %v", err, err)
}

func TestVaultCreateNilIdentityReturnsValidationError(t *testing.T) {
	client, err := NewClient(WithAPIClient(mocks.NewMockAPIClient(t)))
	require.NoError(t, err)

	// Create an Item with TypeIdentity but nil Identity — should not panic.
	item := Item{
		Type: ItemTypeIdentity,
		Name: "Identity Without Fields",
	}

	_, err = client.itemToCore(item)
	require.Error(t, err)

	require.True(t, coreerrors.Is(err, coreerrors.KindValidation),
		"expected validation-kind error, got %T: %v", err, err)
}
