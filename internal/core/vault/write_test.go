package vault

import (
	"context"
	"testing"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	mocks "github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// CreateCipher
// ---------------------------------------------------------------------------

func TestCreateCipherEncryptsAndUpdatesSnapshot(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	input := Item{
		Type:     TypeLogin,
		Name:     "My Login",
		Notes:    "some notes",
		Favorite: true,
		FolderID: "f1",
		Login: &Login{
			Username: "alice",
			Password: "p@ss",
			TOTP:     "otpauth://totp/secret",
			URIs: []URI{
				{URI: "https://example.com", Match: 0},
			},
		},
		Fields: []Field{
			{Name: "custom", Value: "val", Type: 0, LinkedID: 0},
		},
	}

	encrypted := ports.EncryptedCipher{
		ID:       "", // not yet assigned
		Type:     TypeLogin,
		Name:     "enc-name",
		Notes:    "enc-notes",
		Favorite: true,
		FolderID: "f1",
		Login: &ports.EncryptedLoginCipher{
			Username: "enc-user",
			Password: "enc-pass",
			TOTP:     "enc-totp",
			URIs:     []ports.EncryptedLoginURI{{URI: "enc-uri", Match: 0}},
		},
		Fields: []ports.EncryptedCipherField{
			{Name: "enc-custom", Value: "enc-val", Type: 0, LinkedID: 0},
		},
	}

	returned := ports.EncryptedCipher{
		ID:       "c1",
		Type:     TypeLogin,
		Name:     "enc-name",
		Notes:    "enc-notes",
		Favorite: true,
		FolderID: "f1",
		Login: &ports.EncryptedLoginCipher{
			Username: "enc-user",
			Password: "enc-pass",
			TOTP:     "enc-totp",
			URIs:     []ports.EncryptedLoginURI{{URI: "enc-uri", Match: 0}},
		},
		Fields: []ports.EncryptedCipherField{
			{Name: "enc-custom", Value: "enc-val", Type: 0, LinkedID: 0},
		},
	}

	decrypted := ports.Cipher{
		ID:       "c1",
		Type:     TypeLogin,
		Name:     "My Login",
		Notes:    "some notes",
		Favorite: true,
		FolderID: "f1",
		Login: &ports.LoginCipher{
			Username: "alice",
			Password: "p@ss",
			TOTP:     "otpauth://totp/secret",
			URIs:     []ports.LoginURI{{URI: "https://example.com", Match: 0}},
		},
		Fields: []ports.CipherField{
			{Name: "custom", Value: "val", Type: 0, LinkedID: 0},
		},
	}

	// Expect encrypt with plaintext ports.Cipher built from input.
	crypto.EXPECT().
		EncryptCipher(ctxb(), key, mock.MatchedBy(
			func(cipher ports.Cipher) bool {
				return cipher.Type == TypeLogin &&
					cipher.Name == "My Login" &&
					cipher.Notes == "some notes" &&
					cipher.Favorite == true &&
					cipher.FolderID == "f1" &&
					cipher.Login != nil &&
					cipher.Login.Username == "alice" &&
					cipher.Login.Password == "p@ss" &&
					cipher.Login.TOTP == "otpauth://totp/secret" &&
					len(cipher.Login.URIs) == 1 &&
					cipher.Login.URIs[0].URI == "https://example.com" &&
					len(cipher.Fields) == 1 &&
					cipher.Fields[0].Name == "custom" &&
					cipher.Fields[0].Value == "val"
			},
		)).
		Return(encrypted, nil).
		Once()

	api.EXPECT().
		CreateCipher(ctxb(), encrypted).
		Return(returned, nil).
		Once()

	crypto.EXPECT().
		DecryptCipher(ctxb(), key, returned).
		Return(decrypted, nil).
		Once()

	result, err := svc.CreateCipher(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, "c1", result.ID)
	assert.Equal(t, "My Login", result.Name)

	// Snapshot must contain the new item.
	item, ok, err := svc.Get("c1")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "My Login", item.Name)
	assert.Equal(t, "some notes", item.Notes)
	assert.True(t, item.Favorite)
	assert.Equal(t, "f1", item.FolderID)
	require.NotNil(t, item.Login)
	assert.Equal(t, "alice", item.Login.Username)
	assert.Equal(t, "p@ss", item.Login.Password)
	assert.Equal(t, "otpauth://totp/secret", item.Login.TOTP)
	require.Len(t, item.Login.URIs, 1)
	assert.Equal(t, "https://example.com", item.Login.URIs[0].URI)
	require.Len(t, item.Fields, 1)
	assert.Equal(t, "custom", item.Fields[0].Name)
	assert.Equal(t, "val", item.Fields[0].Value)
}

func TestCreateCipherDoesNotUpdateSnapshotOnRemoteError(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	// Pre-populate snapshot.
	svc.snapshot = NewSnapshot(
		[]Item{{ID: "existing", Name: "Existing"}},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	input := Item{
		Type: TypeSecureNote,
		Name: "New Note",
		SecureNote: &SecureNote{
			Type: 0,
		},
	}

	crypto.EXPECT().
		EncryptCipher(ctxb(), key, mock.Anything).
		Return(ports.EncryptedCipher{Type: TypeSecureNote, Name: "enc-new"}, nil).
		Once()

	// API returns error.
	api.EXPECT().
		CreateCipher(ctxb(), mock.Anything).
		Return(ports.EncryptedCipher{}, assert.AnError).
		Once()

	_, err := svc.CreateCipher(context.Background(), input)
	require.Error(t, err)

	// Snapshot must be unchanged.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "existing", items[0].ID)
	assert.Equal(t, "Existing", items[0].Name)
}

// ---------------------------------------------------------------------------
// UpdateCipher
// ---------------------------------------------------------------------------

func TestUpdateCipherEncryptsAndReplacesSnapshot(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	// Pre-populate snapshot with the item to update.
	svc.snapshot = NewSnapshot(
		[]Item{{ID: "c1", Type: TypeSecureNote, Name: "Old Note", SecureNote: &SecureNote{Type: 0}}},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	// Test updating to a SecureNote.
	input := Item{
		Type: TypeSecureNote,
		Name: "Updated SecureNote",
		SecureNote: &SecureNote{
			Type: 1,
		},
	}

	encrypted := ports.EncryptedCipher{
		Type: TypeSecureNote,
		Name: "enc-updated",
		SecureNote: &ports.EncryptedSecureNoteCipher{
			Type: 1,
		},
	}

	returned := ports.EncryptedCipher{
		ID:   "c1",
		Type: TypeSecureNote,
		Name: "enc-updated",
		SecureNote: &ports.EncryptedSecureNoteCipher{
			Type: 1,
		},
	}

	decrypted := ports.Cipher{
		ID:   "c1",
		Type: TypeSecureNote,
		Name: "Updated SecureNote",
		SecureNote: &ports.SecureNoteCipher{
			Type: 1,
		},
	}

	crypto.EXPECT().
		EncryptCipher(ctxb(), key, mock.MatchedBy(func(c ports.Cipher) bool {
			return c.Type == TypeSecureNote && c.Name == "Updated SecureNote" &&
				c.SecureNote != nil && c.SecureNote.Type == 1
		})).
		Return(encrypted, nil).
		Once()

	api.EXPECT().
		UpdateCipher(ctxb(), "c1", encrypted).
		Return(returned, nil).
		Once()

	crypto.EXPECT().
		DecryptCipher(ctxb(), key, returned).
		Return(decrypted, nil).
		Once()

	result, err := svc.UpdateCipher(context.Background(), "c1", input)
	require.NoError(t, err)
	assert.Equal(t, "c1", result.ID)
	assert.Equal(t, "Updated SecureNote", result.Name)

	// Snapshot must be replaced.
	item, ok, err := svc.Get("c1")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "Updated SecureNote", item.Name)
	require.NotNil(t, item.SecureNote)
	assert.Equal(t, 1, item.SecureNote.Type)
}

func TestUpdateCipherEncryptsAndReplacesCard(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	svc.snapshot = NewSnapshot(
		[]Item{{ID: "c1", Type: TypeCard, Name: "Old Card"}},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	input := Item{
		Type: TypeCard,
		Name: "Updated Card",
		Card: &Card{
			CardholderName: "Alice",
			Brand:          "Visa",
			Number:         "4111111111111111",
			ExpMonth:       "12",
			ExpYear:        "2028",
			Code:           "123",
		},
	}

	crypto.EXPECT().
		EncryptCipher(ctxb(), key, mock.MatchedBy(func(c ports.Cipher) bool {
			return c.Type == TypeCard && c.Name == "Updated Card" &&
				c.Card != nil && c.Card.CardholderName == "Alice" && c.Card.Brand == "Visa"
		})).
		Return(ports.EncryptedCipher{
			ID:   "c1",
			Type: TypeCard,
			Name: "enc-card",
			Card: &ports.EncryptedCardCipher{
				CardholderName: "enc-holder",
				Brand:          "enc-brand",
				Number:         "enc-num",
				ExpMonth:       "enc-month",
				ExpYear:        "enc-year",
				Code:           "enc-code",
			},
		}, nil).
		Once()

	api.EXPECT().
		UpdateCipher(ctxb(), "c1", mock.Anything).
		Return(ports.EncryptedCipher{
			ID:   "c1",
			Type: TypeCard,
			Name: "enc-card",
			Card: &ports.EncryptedCardCipher{
				CardholderName: "enc-holder",
				Brand:          "enc-brand",
				Number:         "enc-num",
				ExpMonth:       "enc-month",
				ExpYear:        "enc-year",
				Code:           "enc-code",
			},
		}, nil).
		Once()

	crypto.EXPECT().
		DecryptCipher(ctxb(), key, mock.Anything).
		Return(ports.Cipher{
			ID:   "c1",
			Type: TypeCard,
			Name: "Updated Card",
			Card: &ports.CardCipher{
				CardholderName: "Alice",
				Brand:          "Visa",
				Number:         "4111111111111111",
				ExpMonth:       "12",
				ExpYear:        "2028",
				Code:           "123",
			},
		}, nil).
		Once()

	result, err := svc.UpdateCipher(context.Background(), "c1", input)
	require.NoError(t, err)
	assert.Equal(t, "Updated Card", result.Name)
	require.NotNil(t, result.Card)
	assert.Equal(t, "Alice", result.Card.CardholderName)
	assert.Equal(t, "Visa", result.Card.Brand)
}

func TestUpdateCipherEncryptsAndReplacesIdentity(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	svc.snapshot = NewSnapshot(
		[]Item{{ID: "c1", Type: TypeIdentity, Name: "Old Identity"}},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	input := Item{
		Type: TypeIdentity,
		Name: "Updated Identity",
		Identity: &Identity{
			Title:          "Mr",
			FirstName:      "John",
			MiddleName:     "M",
			LastName:       "Doe",
			Address1:       "123 Main St",
			City:           "Metropolis",
			State:          "NY",
			PostalCode:     "10001",
			Country:        "US",
			Company:        "ACME",
			Email:          "john@example.com",
			Phone:          "555-0100",
			SSN:            "123-45-6789",
			Username:       "jdoe",
			PassportNumber: "X123456",
			LicenseNumber:  "D123-4567-890",
		},
	}

	crypto.EXPECT().
		EncryptCipher(ctxb(), key, mock.MatchedBy(func(c ports.Cipher) bool {
			return c.Type == TypeIdentity && c.Name == "Updated Identity" &&
				c.Identity != nil && c.Identity.FirstName == "John" && c.Identity.LastName == "Doe"
		})).
		Return(ports.EncryptedCipher{
			ID:   "c1",
			Type: TypeIdentity,
			Name: "enc-identity",
			Identity: &ports.EncryptedIdentityCipher{
				Title:          "enc-title",
				FirstName:      "enc-first",
				MiddleName:     "enc-mid",
				LastName:       "enc-last",
				Address1:       "enc-addr1",
				City:           "enc-city",
				State:          "enc-state",
				PostalCode:     "enc-zip",
				Country:        "enc-country",
				Company:        "enc-company",
				Email:          "enc-email",
				Phone:          "enc-phone",
				SSN:            "enc-ssn",
				Username:       "enc-user",
				PassportNumber: "enc-passport",
				LicenseNumber:  "enc-license",
			},
		}, nil).
		Once()

	api.EXPECT().
		UpdateCipher(ctxb(), "c1", mock.Anything).
		Return(ports.EncryptedCipher{
			ID:   "c1",
			Type: TypeIdentity,
			Name: "enc-identity",
			Identity: &ports.EncryptedIdentityCipher{
				Title:          "enc-title",
				FirstName:      "enc-first",
				MiddleName:     "enc-mid",
				LastName:       "enc-last",
				Address1:       "enc-addr1",
				City:           "enc-city",
				State:          "enc-state",
				PostalCode:     "enc-zip",
				Country:        "enc-country",
				Company:        "enc-company",
				Email:          "enc-email",
				Phone:          "enc-phone",
				SSN:            "enc-ssn",
				Username:       "enc-user",
				PassportNumber: "enc-passport",
				LicenseNumber:  "enc-license",
			},
		}, nil).
		Once()

	crypto.EXPECT().
		DecryptCipher(ctxb(), key, mock.Anything).
		Return(ports.Cipher{
			ID:   "c1",
			Type: TypeIdentity,
			Name: "Updated Identity",
			Identity: &ports.IdentityCipher{
				Title:          "Mr",
				FirstName:      "John",
				MiddleName:     "M",
				LastName:       "Doe",
				Address1:       "123 Main St",
				City:           "Metropolis",
				State:          "NY",
				PostalCode:     "10001",
				Country:        "US",
				Company:        "ACME",
				Email:          "john@example.com",
				Phone:          "555-0100",
				SSN:            "123-45-6789",
				Username:       "jdoe",
				PassportNumber: "X123456",
				LicenseNumber:  "D123-4567-890",
			},
		}, nil).
		Once()

	result, err := svc.UpdateCipher(context.Background(), "c1", input)
	require.NoError(t, err)
	assert.Equal(t, "Updated Identity", result.Name)
	require.NotNil(t, result.Identity)
	assert.Equal(t, "Mr", result.Identity.Title)
	assert.Equal(t, "John", result.Identity.FirstName)
	assert.Equal(t, "Doe", result.Identity.LastName)
	assert.Equal(t, "jdoe", result.Identity.Username)
}

func TestUpdateCipherDoesNotReplaceSnapshotOnRemoteError(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	svc.snapshot = NewSnapshot(
		[]Item{{ID: "c1", Type: TypeLogin, Name: "Original", Login: &Login{Username: "alice"}}},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	input := Item{
		Type: TypeLogin,
		Name: "Changed Name",
		Login: &Login{
			Username: "bob",
		},
	}

	crypto.EXPECT().
		EncryptCipher(ctxb(), key, mock.Anything).
		Return(ports.EncryptedCipher{ID: "c1", Type: TypeLogin, Name: "enc-changed"}, nil).
		Once()

	// API returns error.
	api.EXPECT().
		UpdateCipher(ctxb(), "c1", mock.Anything).
		Return(ports.EncryptedCipher{}, assert.AnError).
		Once()

	_, err := svc.UpdateCipher(context.Background(), "c1", input)
	require.Error(t, err)

	// Snapshot must be unchanged.
	item, ok, err := svc.Get("c1")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "Original", item.Name)
	assert.Equal(t, "alice", item.Login.Username)
}

// ---------------------------------------------------------------------------
// TrashCipher
// ---------------------------------------------------------------------------

func TestTrashCipherRemovesAfterSuccess(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	svc.snapshot = NewSnapshot(
		[]Item{
			{ID: "c1", Name: "Item One"},
			{ID: "c2", Name: "Item Two"},
		},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	api.EXPECT().
		TrashCipher(ctxb(), "c1").
		Return(nil).
		Once()

	err := svc.TrashCipher(context.Background(), "c1")
	require.NoError(t, err)

	// Snapshot must no longer contain c1.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "c2", items[0].ID)

	_, ok, _ := svc.Get("c1")
	assert.False(t, ok)
}

func TestTrashCipherDoesNotRemoveOnError(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	svc.snapshot = NewSnapshot(
		[]Item{
			{ID: "c1", Name: "Item One"},
			{ID: "c2", Name: "Item Two"},
		},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	api.EXPECT().
		TrashCipher(ctxb(), "c1").
		Return(assert.AnError).
		Once()

	err := svc.TrashCipher(context.Background(), "c1")
	require.Error(t, err)

	// Snapshot must be unchanged.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 2)
}

// ---------------------------------------------------------------------------
// RestoreCipher
// ---------------------------------------------------------------------------

func TestRestoreCipherDecryptsAndUpserts(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	// Snapshot starts with existing items but not c1.
	svc.snapshot = NewSnapshot(
		[]Item{{ID: "c2", Name: "Other Item"}},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	returned := ports.EncryptedCipher{
		ID:   "c1",
		Type: TypeLogin,
		Name: "enc-restored",
	}

	decrypted := ports.Cipher{
		ID:   "c1",
		Type: TypeLogin,
		Name: "Restored Login",
	}

	api.EXPECT().
		RestoreCipher(ctxb(), "c1").
		Return(returned, nil).
		Once()

	crypto.EXPECT().
		DecryptCipher(ctxb(), key, returned).
		Return(decrypted, nil).
		Once()

	result, err := svc.RestoreCipher(context.Background(), "c1")
	require.NoError(t, err)
	assert.Equal(t, "c1", result.ID)
	assert.Equal(t, "Restored Login", result.Name)

	// Snapshot must contain both items.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 2)

	got, ok, err := svc.Get("c1")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "Restored Login", got.Name)
}

func TestRestoreCipherUpsertsExistingItemInSnapshot(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	// c1 already exists in snapshot.
	svc.snapshot = NewSnapshot(
		[]Item{{ID: "c1", Name: "Old Name"}},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	returned := ports.EncryptedCipher{
		ID:   "c1",
		Type: TypeLogin,
		Name: "enc-restored",
	}

	decrypted := ports.Cipher{
		ID:   "c1",
		Type: TypeLogin,
		Name: "Restored Name",
	}

	api.EXPECT().
		RestoreCipher(ctxb(), "c1").
		Return(returned, nil).
		Once()

	crypto.EXPECT().
		DecryptCipher(ctxb(), key, returned).
		Return(decrypted, nil).
		Once()

	result, err := svc.RestoreCipher(context.Background(), "c1")
	require.NoError(t, err)
	assert.Equal(t, "Restored Name", result.Name)

	// Snapshot must have only c1 with new name.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "Restored Name", items[0].Name)
}

func TestRestoreCipherDoesNotUpsertOnRemoteError(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	svc.snapshot = NewSnapshot(
		[]Item{{ID: "c1", Name: "Original"}},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	api.EXPECT().
		RestoreCipher(ctxb(), "c1").
		Return(ports.EncryptedCipher{}, assert.AnError).
		Once()

	_, err := svc.RestoreCipher(context.Background(), "c1")
	require.Error(t, err)

	// Snapshot unchanged.
	item, ok, err := svc.Get("c1")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "Original", item.Name)
}

// ---------------------------------------------------------------------------
// DeleteCipher (permanent)
// ---------------------------------------------------------------------------

func TestDeleteCipherPermanentRemovesAfterSuccess(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	svc.snapshot = NewSnapshot(
		[]Item{
			{ID: "c1", Name: "Item One"},
			{ID: "c2", Name: "Item Two"},
		},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	api.EXPECT().
		DeleteCipher(ctxb(), "c1").
		Return(nil).
		Once()

	err := svc.DeleteCipher(context.Background(), "c1")
	require.NoError(t, err)

	// Snapshot must no longer contain c1.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "c2", items[0].ID)
}

func TestDeleteCipherDoesNotRemoveOnError(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	svc.snapshot = NewSnapshot(
		[]Item{
			{ID: "c1", Name: "Item One"},
			{ID: "c2", Name: "Item Two"},
		},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	api.EXPECT().
		DeleteCipher(ctxb(), "c1").
		Return(assert.AnError).
		Once()

	err := svc.DeleteCipher(context.Background(), "c1")
	require.Error(t, err)

	// Snapshot unchanged.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 2)
}

// ---------------------------------------------------------------------------
// Locked guard for all write operations
// ---------------------------------------------------------------------------

func TestCipherWritesLockedReturnLocked(t *testing.T) {
	t.Parallel()

	svc := NewService(Dependencies{
		Locked: true,
	})

	ctx := context.Background()

	_, err := svc.CreateCipher(ctx, Item{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked), "CreateCipher: expected KindLocked")

	_, err = svc.UpdateCipher(ctx, "id", Item{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked), "UpdateCipher: expected KindLocked")

	err = svc.TrashCipher(ctx, "id")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked), "TrashCipher: expected KindLocked")

	_, err = svc.RestoreCipher(ctx, "id")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked), "RestoreCipher: expected KindLocked")

	err = svc.DeleteCipher(ctx, "id")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked), "DeleteCipher: expected KindLocked")
}
