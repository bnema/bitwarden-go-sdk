package crypto

import (
	"context"
	"testing"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testUserKey64 returns a deterministic 64-byte user key:
// bytes 0-31 = enc key, bytes 32-63 = mac key.
func testUserKey64() ports.UserKey {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	return ports.UserKey{Bytes: key}
}

// --------------------------------------------------------------------------
// Cipher encrypt/decrypt
// --------------------------------------------------------------------------

func TestCipherEncryptDecryptRoundtrip(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()

	original := ports.Cipher{
		ID:       "cipher-abc-123",
		FolderID: "folder-1",
		Name:     "My Test Login",
		Username: "alice@example.com",
		Password: "s3cret!",
		URI:      "https://login.example.com",
	}

	enc, err := eng.EncryptCipher(context.Background(), key, original)
	require.NoError(t, err)
	assert.Equal(t, "cipher-abc-123", enc.ID, "ID must be preserved")
	assert.Equal(t, "folder-1", enc.FolderID, "FolderID must be preserved")
	assert.Equal(t, 1, enc.Type, "must be login type 1")
	assert.NotEmpty(t, enc.Name, "encrypted name must not be empty")
	assert.NotEqual(t, original.Name, enc.Name, "encrypted name must differ from plaintext")
	assert.NotEmpty(t, enc.Username, "encrypted username must not be empty")
	assert.NotEqual(t, original.Username, enc.Username, "encrypted username must differ from plaintext")
	assert.NotEmpty(t, enc.Password, "encrypted password must not be empty")
	assert.NotEqual(t, original.Password, enc.Password, "encrypted password must differ from plaintext")
	assert.NotEmpty(t, enc.URI, "encrypted URI must not be empty")
	assert.NotEqual(t, original.URI, enc.URI, "encrypted URI must differ from plaintext")

	// Roundtrip: decrypt must recover all original fields.
	dec, err := eng.DecryptCipher(context.Background(), key, enc)
	require.NoError(t, err)
	assert.Equal(t, "cipher-abc-123", dec.ID, "ID must survive roundtrip")
	assert.Equal(t, "folder-1", dec.FolderID, "FolderID must survive roundtrip")
	assert.Equal(t, "My Test Login", dec.Name, "name must decrypt to original")
	assert.Equal(t, "alice@example.com", dec.Username, "username must decrypt to original")
	assert.Equal(t, "s3cret!", dec.Password, "password must decrypt to original")
	assert.Equal(t, "https://login.example.com", dec.URI, "URI must decrypt to original")
}

func TestDecryptCipherDeterministicType2(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()

	// Build deterministic type 2 EncStrings by hand using a fixed IV.
	encKey := key.Bytes[:32]
	macKey := key.Bytes[32:64]

	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(16 - i)
	}

	buildEncStr := func(plaintext []byte) string {
		ct, err := aes256cbcEncrypt(encKey, iv, plaintext)
		require.NoError(t, err)
		mac := computeMac(macKey, iv, ct)
		encStr := EncString{Type: 2, IV: iv, Data: ct, MAC: mac}
		s, serErr := encStr.String()
		require.NoError(t, serErr)
		return s
	}

	nameEnc := buildEncStr([]byte("Known Plaintext"))
	userEnc := buildEncStr([]byte("det-user"))
	passEnc := buildEncStr([]byte("det-pass"))
	uriEnc := buildEncStr([]byte("det://uri"))

	dec, err := eng.DecryptCipher(context.Background(), key, ports.EncryptedCipher{
		ID:       "det-456",
		Name:     nameEnc,
		Username: userEnc,
		Password: passEnc,
		URI:      uriEnc,
	})
	require.NoError(t, err)
	assert.Equal(t, "det-456", dec.ID)
	assert.Equal(t, "Known Plaintext", dec.Name)
	assert.Equal(t, "det-user", dec.Username)
	assert.Equal(t, "det-pass", dec.Password)
	assert.Equal(t, "det://uri", dec.URI)
}

func TestDecryptCipherDeterministicType0(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()
	encKey := key.Bytes[:32]

	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 1)
	}

	ct, err := aes256cbcEncrypt(encKey, iv, []byte("legacy plaintext"))
	require.NoError(t, err)
	encStr, err := EncString{Type: 0, IV: iv, Data: ct}.String()
	require.NoError(t, err)

	dec, err := eng.DecryptCipher(context.Background(), key, ports.EncryptedCipher{
		ID:   "legacy-1",
		Name: encStr,
	})
	require.NoError(t, err)
	assert.Equal(t, "legacy plaintext", dec.Name)
}

func TestDecryptCipherRoundtripWithEmptyFields(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()

	original := ports.Cipher{
		ID:       "c-empty",
		Name:     "",
		Username: "",
		Password: "",
		URI:      "",
	}

	enc, err := eng.EncryptCipher(context.Background(), key, original)
	require.NoError(t, err)
	assert.Equal(t, "c-empty", enc.ID)
	assert.NotEmpty(t, enc.Name, "even empty name encrypts to non-empty enc string")
	assert.NotEmpty(t, enc.Username, "even empty username encrypts to non-empty enc string")
	assert.NotEmpty(t, enc.Password, "even empty password encrypts to non-empty enc string")
	assert.NotEmpty(t, enc.URI, "even empty URI encrypts to non-empty enc string")

	dec, err := eng.DecryptCipher(context.Background(), key, enc)
	require.NoError(t, err)
	assert.Equal(t, "c-empty", dec.ID)
	assert.Empty(t, dec.Name)
	assert.Empty(t, dec.Username)
	assert.Empty(t, dec.Password)
	assert.Empty(t, dec.URI)
}

func TestEncryptCipherInvalidKeyLength(t *testing.T) {
	eng := NewEngine()

	_, err := eng.EncryptCipher(context.Background(),
		ports.UserKey{Bytes: make([]byte, 31)},
		ports.Cipher{Name: "test"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindValidation) || errors.Is(err, errors.KindCrypto),
		"expected KindValidation or KindCrypto, got %v", err)

	_, err = eng.EncryptCipher(context.Background(),
		ports.UserKey{Bytes: make([]byte, 65)},
		ports.Cipher{Name: "test"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindValidation) || errors.Is(err, errors.KindCrypto),
		"expected KindValidation or KindCrypto, got %v", err)
}

func TestDecryptCipherInvalidKeyLength(t *testing.T) {
	eng := NewEngine()

	_, err := eng.DecryptCipher(context.Background(),
		ports.UserKey{Bytes: make([]byte, 32)},
		ports.EncryptedCipher{Name: "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAA|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindValidation) || errors.Is(err, errors.KindCrypto))
}

func TestDecryptCipherMalformedEncString(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()

	// Malformed Name.
	_, err := eng.DecryptCipher(context.Background(), key,
		ports.EncryptedCipher{Name: "not-an-enc-string"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto), "expected KindCrypto, got %v", err)

	_, err = eng.DecryptCipher(context.Background(), key,
		ports.EncryptedCipher{Name: "9.xxx"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto), "expected KindCrypto, got %v", err)

	// Malformed Username (explicitly, without leaking plaintext/ciphertext).
	_, err = eng.DecryptCipher(context.Background(), key,
		ports.EncryptedCipher{
			Name:     "2.AAAAAAAAAAAAAAAAAAAAAA==|AA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Username: "not-valid",
		})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto), "malformed username must return KindCrypto")

	// Malformed Password.
	_, err = eng.DecryptCipher(context.Background(), key,
		ports.EncryptedCipher{
			Name:     "2.AAAAAAAAAAAAAAAAAAAAAA==|AA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Password: "bad-enc",
		})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto), "malformed password must return KindCrypto")

	// Malformed URI.
	_, err = eng.DecryptCipher(context.Background(), key,
		ports.EncryptedCipher{
			Name: "2.AAAAAAAAAAAAAAAAAAAAAA==|AA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			URI:  "bad-enc",
		})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto), "malformed URI must return KindCrypto")
}

func TestDecryptCipherMACMismatch(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()

	// Encrypt a cipher legitimately.
	orig := ports.Cipher{
		ID:       "mac-test",
		Name:     "tamper me",
		Username: "tamper-user",
		Password: "tamper-pass",
		URI:      "tamper://uri",
	}
	enc, err := eng.EncryptCipher(context.Background(), key, orig)
	require.NoError(t, err)

	// Corrupt each field's MAC in turn and verify KindCrypto.
	tamper := func(encField string) string {
		parsed, parseErr := ParseEncString(encField)
		require.NoError(t, parseErr)
		require.Equal(t, 2, parsed.Type)
		corruptedMAC := make([]byte, len(parsed.MAC))
		copy(corruptedMAC, parsed.MAC)
		corruptedMAC[0] ^= 0xff
		parsed.MAC = corruptedMAC
		s, serErr := parsed.String()
		require.NoError(t, serErr)
		return s
	}

	// Tamper Username.
	_, err = eng.DecryptCipher(context.Background(), key, ports.EncryptedCipher{
		ID:       enc.ID,
		Name:     enc.Name,
		Username: tamper(enc.Username),
		Password: enc.Password,
		URI:      enc.URI,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto), "tampered username MAC must return KindCrypto")

	// Tamper Password.
	_, err = eng.DecryptCipher(context.Background(), key, ports.EncryptedCipher{
		ID:       enc.ID,
		Name:     enc.Name,
		Username: enc.Username,
		Password: tamper(enc.Password),
		URI:      enc.URI,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto), "tampered password MAC must return KindCrypto")

	// Tamper URI.
	_, err = eng.DecryptCipher(context.Background(), key, ports.EncryptedCipher{
		ID:       enc.ID,
		Name:     enc.Name,
		Username: enc.Username,
		Password: enc.Password,
		URI:      tamper(enc.URI),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto), "tampered URI MAC must return KindCrypto")
}

func TestCipherCompositeEncryptDecryptAllMappedFields(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()
	original := ports.Cipher{
		ID:       "all-fields",
		Type:     1,
		Name:     "Full login",
		Notes:    "private notes",
		Favorite: true,
		Login: &ports.LoginCipher{
			Username: "alice",
			Password: "pass",
			TOTP:     "otpauth://totp/example",
			URIs:     []ports.LoginURI{{URI: "https://example.com", Match: 1, URIChecksum: "checksum"}},
		},
		Card: &ports.CardCipher{CardholderName: "Alice", Brand: "Visa", Number: "4111111111111111", ExpMonth: "01", ExpYear: "2030", Code: "123"},
		Identity: &ports.IdentityCipher{
			Title: "Dr", FirstName: "Alice", MiddleName: "B", LastName: "Example",
			Address1: "1 Main", Address2: "Apt 2", Address3: "Floor 3", City: "Paris", State: "IDF", PostalCode: "75000", Country: "FR",
			Company: "Example Co", Email: "alice@example.com", Phone: "+330000000", SSN: "ssn", Username: "alice-id", PassportNumber: "passport", LicenseNumber: "license",
		},
		Fields: []ports.CipherField{{Name: "custom", Value: "value", Type: 0, LinkedID: 100}},
	}

	enc, err := eng.EncryptCipher(context.Background(), key, original)
	require.NoError(t, err)
	assert.Equal(t, original.Favorite, enc.Favorite)
	assert.NotEqual(t, original.Notes, enc.Notes)
	assert.NotEqual(t, original.Login.TOTP, enc.Login.TOTP)
	assert.Equal(t, original.Login.URIs[0].Match, enc.Login.URIs[0].Match)
	assert.NotEqual(t, original.Login.URIs[0].URIChecksum, enc.Login.URIs[0].URIChecksum)
	assert.NotEqual(t, original.Card.Number, enc.Card.Number)
	assert.NotEqual(t, original.Identity.PassportNumber, enc.Identity.PassportNumber)
	assert.Equal(t, original.Fields[0].Type, enc.Fields[0].Type)
	assert.Equal(t, original.Fields[0].LinkedID, enc.Fields[0].LinkedID)
	assert.NotEqual(t, original.Fields[0].Value, enc.Fields[0].Value)

	dec, err := eng.DecryptCipher(context.Background(), key, enc)
	require.NoError(t, err)
	assert.Equal(t, original, dec)
}

func TestSecureNoteCipherEncryptDecrypt(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()
	original := ports.Cipher{ID: "note", Type: 2, Name: "Secure Note", Notes: "note body", Favorite: true, SecureNote: &ports.SecureNoteCipher{Type: 0}}

	enc, err := eng.EncryptCipher(context.Background(), key, original)
	require.NoError(t, err)
	assert.NotEqual(t, original.Notes, enc.Notes)
	assert.Equal(t, 0, enc.SecureNote.Type)

	dec, err := eng.DecryptCipher(context.Background(), key, enc)
	require.NoError(t, err)
	assert.Equal(t, original, dec)
}

func TestEncryptCipherContextCancellation(t *testing.T) {
	eng := NewEngine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := eng.EncryptCipher(ctx, testUserKey64(), ports.Cipher{Name: "test"})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestDecryptCipherContextCancellation(t *testing.T) {
	eng := NewEngine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := eng.DecryptCipher(ctx, testUserKey64(),
		ports.EncryptedCipher{Name: "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAA|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

// --------------------------------------------------------------------------
// Folder name encrypt/decrypt
// --------------------------------------------------------------------------

func TestFolderEncryptDecryptRoundtrip(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()

	encrypted, err := eng.EncryptFolderName(context.Background(), key, "My Folder")
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, "My Folder", encrypted)

	decrypted, err := eng.DecryptFolderName(context.Background(), key, encrypted)
	require.NoError(t, err)
	assert.Equal(t, "My Folder", decrypted)
}

func TestFolderRoundtripWithEmptyName(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()

	encrypted, err := eng.EncryptFolderName(context.Background(), key, "")
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := eng.DecryptFolderName(context.Background(), key, encrypted)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestFolderEncryptInvalidKeyLength(t *testing.T) {
	eng := NewEngine()

	_, err := eng.EncryptFolderName(context.Background(),
		ports.UserKey{Bytes: make([]byte, 31)}, "test")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindValidation) || errors.Is(err, errors.KindCrypto))
}

func TestFolderDecryptMalformedEncString(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()

	_, err := eng.DecryptFolderName(context.Background(), key, "not-an-enc-string")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto))
}

func TestFolderDecryptMACMismatch(t *testing.T) {
	eng := NewEngine()
	key := testUserKey64()

	encrypted, err := eng.EncryptFolderName(context.Background(), key, "My Folder")
	require.NoError(t, err)

	parsed, parseErr := ParseEncString(encrypted)
	require.NoError(t, parseErr)
	require.Equal(t, 2, parsed.Type)

	corruptedMAC := make([]byte, len(parsed.MAC))
	copy(corruptedMAC, parsed.MAC)
	corruptedMAC[0] ^= 0xff
	parsed.MAC = corruptedMAC

	badSerialized, serErr := parsed.String()
	require.NoError(t, serErr)

	_, err = eng.DecryptFolderName(context.Background(), key, badSerialized)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto))
}

func TestFolderContextCancellation(t *testing.T) {
	eng := NewEngine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := eng.EncryptFolderName(ctx, testUserKey64(), "test")
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)

	_, err = eng.DecryptFolderName(ctx, testUserKey64(),
		"2.AAAAAAAAAAAAAAAAAAAAAA==|AAAA|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
