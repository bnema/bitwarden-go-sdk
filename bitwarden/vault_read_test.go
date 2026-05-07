package bitwarden

import (
	"context"
	"testing"
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/core/vault"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestClientSyncThenListSearchGet(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		withIdentityClient(identity),
		withCryptoEngine(crypto),
		withTokenStore(store),
		withAPIClient(api),
	)
	require.NoError(t, err)
	require.True(t, client.IsLocked())

	// Complete a login to unlock the client and set the user key.
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

	// Now set up mock expectations for Sync.
	api.EXPECT().
		Sync(mock.Anything, ports.SyncOptions{}).
		Return(ports.SyncResult{
			Folders: []ports.EncryptedFolder{
				{ID: "f1", Name: "enc-banking"},
			},
			Ciphers: []ports.EncryptedCipher{
				{
					ID: "c1", Type: 1, Name: "enc-login",
					Notes: "enc-note", Favorite: true, FolderID: "f1",
					Login: &ports.EncryptedLoginCipher{
						Username: "enc-user",
						Password: "enc-pass",
						TOTP:     "enc-totp",
						URIs:     []ports.EncryptedLoginURI{{URI: "enc-uri", Match: 0}},
					},
					Fields: []ports.EncryptedCipherField{
						{Name: "enc-fname", Value: "enc-fvalue", Type: 0, LinkedID: 0},
					},
				},
			},
		}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(mock.Anything, userKey, "enc-banking").
		Return("Banking", nil).
		Once()

	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, ports.EncryptedCipher{
			ID: "c1", Type: 1, Name: "enc-login",
			Notes: "enc-note", Favorite: true, FolderID: "f1",
			Login: &ports.EncryptedLoginCipher{
				Username: "enc-user", Password: "enc-pass", TOTP: "enc-totp",
				URIs: []ports.EncryptedLoginURI{{URI: "enc-uri", Match: 0}},
			},
			Fields: []ports.EncryptedCipherField{
				{Name: "enc-fname", Value: "enc-fvalue", Type: 0, LinkedID: 0},
			},
		}).
		Return(ports.Cipher{
			ID: "c1", Type: 1, Name: "My Login",
			Notes: "My notes", Favorite: true, FolderID: "f1",
			Login: &ports.LoginCipher{
				Username: "alice", Password: "p@ssw0rd", TOTP: "JBSWY3DPEHPK3PXP",
				URIs: []ports.LoginURI{{URI: "https://example.com", Match: 0}},
			},
			Fields: []ports.CipherField{
				{Name: "custom", Value: "custom-value", Type: 0, LinkedID: 0},
			},
		}, nil).
		Once()

	// Sync.
	err = client.Sync(context.Background())
	require.NoError(t, err)

	// List returns decrypted items.
	items, err := client.Vault().List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	item := items[0]
	assert.Equal(t, ItemID("c1"), item.ID)
	assert.Equal(t, "My Login", item.Name)
	assert.Equal(t, "alice", item.Username)
	assert.Equal(t, "https://example.com", item.URI)
	assert.Equal(t, ItemTypeLogin, item.Type)
	assert.Equal(t, "My notes", item.Notes)
	assert.True(t, item.Favorite)
	assert.Equal(t, "f1", item.FolderID)

	// Password is redacted via *Secret.
	require.NotNil(t, item.Password)
	assert.Equal(t, "[REDACTED]", item.Password.String())
	revealed, err := item.Password.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "p@ssw0rd", revealed.String())
	_ = revealed.Close()

	// TOTP is redacted via *Secret.
	require.NotNil(t, item.TOTP)
	assert.Equal(t, "[REDACTED]", item.TOTP.String())
	revealedTotp, err := item.TOTP.Reveal()
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", revealedTotp.String())
	_ = revealedTotp.Close()

	// URIs.
	require.Len(t, item.URIs, 1)
	assert.Equal(t, "https://example.com", item.URIs[0])

	// Fields.
	require.Len(t, item.Fields, 1)
	assert.Equal(t, "custom", item.Fields[0].Name)
	assert.Equal(t, "custom-value", item.Fields[0].Value)

	// Search by name.
	results, err := client.Vault().Search(context.Background(), "Login")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, ItemID("c1"), results[0].ID)

	// Search by folder name.
	results, err = client.Vault().Search(context.Background(), "Banking")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, ItemID("c1"), results[0].ID)

	// Search non-existent.
	results, err = client.Vault().Search(context.Background(), "nonexistent")
	require.NoError(t, err)
	assert.Empty(t, results)

	// Get by ID.
	got, err := client.Vault().Get(context.Background(), "c1")
	require.NoError(t, err)
	assert.Equal(t, ItemID("c1"), got.ID)
	assert.Equal(t, "My Login", got.Name)

	// Get non-existent returns ErrNotFound.
	_, err = client.Vault().Get(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestVaultReadLocked(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		withIdentityClient(identity),
		withCryptoEngine(crypto),
		withTokenStore(store),
		withAPIClient(api),
	)
	require.NoError(t, err)
	require.True(t, client.IsLocked())

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

	// Lock the client.
	client.Lock()
	require.True(t, client.IsLocked())

	// All read operations must return ErrLocked.
	_, err = client.Vault().List(context.Background())
	require.ErrorIs(t, err, ErrLocked)

	_, err = client.Vault().Search(context.Background(), "anything")
	require.ErrorIs(t, err, ErrLocked)

	_, err = client.Vault().Get(context.Background(), "c1")
	require.ErrorIs(t, err, ErrLocked)

	err = client.Sync(context.Background())
	require.ErrorIs(t, err, ErrLocked)
}

func TestVaultItemMapsCardAndIdentity(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		withIdentityClient(identity),
		withCryptoEngine(crypto),
		withTokenStore(store),
		withAPIClient(api),
	)
	require.NoError(t, err)

	t.Run("card", func(t *testing.T) {
		cardItem := client.vaultItem(vault.Item{
			ID:   "card-1",
			Type: vault.TypeCard,
			Name: "My Card",
			Card: &vault.Card{
				CardholderName: "Alice",
				Brand:          "Visa",
				Number:         "4111111111111111",
				ExpMonth:       "12",
				ExpYear:        "2028",
				Code:           "123",
			},
		})

		assert.Equal(t, ItemTypeCard, cardItem.Type)
		require.NotNil(t, cardItem.Card)
		assert.Equal(t, "Alice", cardItem.Card.CardholderName)
		assert.Equal(t, "Visa", cardItem.Card.Brand)
		assert.Equal(t, "12", cardItem.Card.ExpMonth)
		assert.Equal(t, "2028", cardItem.Card.ExpYear)

		// Number is *Secret redacted with Reveal working.
		require.NotNil(t, cardItem.Card.Number)
		assert.Equal(t, "[REDACTED]", cardItem.Card.Number.String())
		revealed, err := cardItem.Card.Number.Reveal()
		require.NoError(t, err)
		assert.Equal(t, "4111111111111111", revealed.String())
		_ = revealed.Close()

		// Code is *Secret redacted with Reveal working.
		require.NotNil(t, cardItem.Card.Code)
		assert.Equal(t, "[REDACTED]", cardItem.Card.Code.String())
		revealed, err = cardItem.Card.Code.Reveal()
		require.NoError(t, err)
		assert.Equal(t, "123", revealed.String())
		_ = revealed.Close()
	})

	t.Run("identity", func(t *testing.T) {
		identityItem := client.vaultItem(vault.Item{
			ID:   "identity-1",
			Type: vault.TypeIdentity,
			Name: "My Identity",
			Identity: &vault.Identity{
				Title:          "Mr",
				FirstName:      "John",
				MiddleName:     "M",
				LastName:       "Doe",
				Address1:       "123 Main St",
				Address2:       "Apt 4",
				Address3:       "",
				City:           "Metropolis",
				State:          "NY",
				PostalCode:     "10001",
				Country:        "US",
				Company:        "Acme",
				Email:          "john@example.com",
				Phone:          "+1-555-1234",
				SSN:            "123-45-6789",
				Username:       "johndoe",
				PassportNumber: "AB123456",
				LicenseNumber:  "D123-4567-8901",
			},
		})

		assert.Equal(t, ItemTypeIdentity, identityItem.Type)
		require.NotNil(t, identityItem.Identity)
		assert.Equal(t, "Mr", identityItem.Identity.Title)
		assert.Equal(t, "John", identityItem.Identity.FirstName)
		assert.Equal(t, "M", identityItem.Identity.MiddleName)
		assert.Equal(t, "Doe", identityItem.Identity.LastName)
		assert.Equal(t, "123 Main St", identityItem.Identity.Address1)
		assert.Equal(t, "Apt 4", identityItem.Identity.Address2)
		assert.Empty(t, identityItem.Identity.Address3)
		assert.Equal(t, "Metropolis", identityItem.Identity.City)
		assert.Equal(t, "NY", identityItem.Identity.State)
		assert.Equal(t, "10001", identityItem.Identity.PostalCode)
		assert.Equal(t, "US", identityItem.Identity.Country)
		assert.Equal(t, "Acme", identityItem.Identity.Company)
		assert.Equal(t, "john@example.com", identityItem.Identity.Email)
		assert.Equal(t, "+1-555-1234", identityItem.Identity.Phone)
		assert.Equal(t, "johndoe", identityItem.Identity.Username)

		// SSN is *Secret redacted with Reveal working.
		require.NotNil(t, identityItem.Identity.SSN)
		assert.Equal(t, "[REDACTED]", identityItem.Identity.SSN.String())
		revealed, err := identityItem.Identity.SSN.Reveal()
		require.NoError(t, err)
		assert.Equal(t, "123-45-6789", revealed.String())
		_ = revealed.Close()

		// PassportNumber is *Secret redacted with Reveal working.
		require.NotNil(t, identityItem.Identity.PassportNumber)
		assert.Equal(t, "[REDACTED]", identityItem.Identity.PassportNumber.String())
		revealed, err = identityItem.Identity.PassportNumber.Reveal()
		require.NoError(t, err)
		assert.Equal(t, "AB123456", revealed.String())
		_ = revealed.Close()

		// LicenseNumber is *Secret redacted with Reveal working.
		require.NotNil(t, identityItem.Identity.LicenseNumber)
		assert.Equal(t, "[REDACTED]", identityItem.Identity.LicenseNumber.String())
		revealed, err = identityItem.Identity.LicenseNumber.Reveal()
		require.NoError(t, err)
		assert.Equal(t, "D123-4567-8901", revealed.String())
		_ = revealed.Close()
	})
}

func TestSyncUsesHTTPVaultClientWithContractTestkit(t *testing.T) {
	// This test verifies that using a mock API client directly (via
	// withAPIClient) triggers the expected HTTP vault client code path.
	// We use the mock to avoid requiring a running server.
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		withIdentityClient(identity),
		withCryptoEngine(crypto),
		withTokenStore(store),
		withAPIClient(api),
	)
	require.NoError(t, err)
	require.True(t, client.IsLocked())

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

	// Set up a minimal sync returning one cipher with a folder.
	api.EXPECT().
		Sync(mock.Anything, ports.SyncOptions{}).
		Return(ports.SyncResult{
			Folders: []ports.EncryptedFolder{
				{ID: "f1", Name: "enc-folder"},
			},
			Ciphers: []ports.EncryptedCipher{
				{ID: "c1", Type: 1, Name: "enc-name"},
			},
		}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(mock.Anything, userKey, "enc-folder").
		Return("Work", nil).
		Once()

	crypto.EXPECT().
		DecryptCipher(mock.Anything, userKey, ports.EncryptedCipher{ID: "c1", Type: 1, Name: "enc-name"}).
		Return(ports.Cipher{ID: "c1", Type: 1, Name: "My Item"}, nil).
		Once()

	// Sync must succeed.
	err = client.Sync(context.Background())
	require.NoError(t, err)

	// Verify data.
	items, err := client.Vault().List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, ItemID("c1"), items[0].ID)
	assert.Equal(t, "My Item", items[0].Name)

	// Lock and verify locked.
	client.Lock()
	err = client.Sync(context.Background())
	require.ErrorIs(t, err, ErrLocked)
}
