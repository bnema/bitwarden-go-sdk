package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pbkdf2Vector matches testdata/bitwarden/crypto/kdf_pbkdf2_vectors.json.
type pbkdf2Vector struct {
	Name            string        `json:"name"`
	Password        string        `json:"password"`
	Email           string        `json:"email"`
	KDF             kdfConfigJSON `json:"kdf"`
	DerivedKeyBytes []byte        `json:"derivedKeyBytes"`
}

// argon2idVector matches testdata/bitwarden/crypto/kdf_argon2id_vectors.json.
type argon2idVector struct {
	Name            string        `json:"name"`
	Password        string        `json:"password"`
	Email           string        `json:"email"`
	KDF             kdfConfigJSON `json:"kdf"`
	DerivedKeyBytes []byte        `json:"derivedKeyBytes"`
}

type kdfConfigJSON struct {
	Type        string `json:"type"`
	Iterations  int    `json:"iterations"`
	MemoryMiB   int    `json:"memoryMiB"`
	Parallelism int    `json:"parallelism"`
}

// fixturesResponse wraps the JSON array in each fixture file.
type pbkdf2Fixtures struct {
	Vectors []pbkdf2Vector `json:"vectors"`
}

type argon2idFixtures struct {
	Vectors []argon2idVector `json:"vectors"`
}

func loadPBKDF2Vector(t *testing.T) pbkdf2Vector {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/bitwarden/crypto/kdf_pbkdf2_vectors.json")
	require.NoError(t, err)
	var f pbkdf2Fixtures
	require.NoError(t, json.Unmarshal(data, &f))
	require.NotEmpty(t, f.Vectors)
	return f.Vectors[0]
}

func loadArgon2idVector(t *testing.T) argon2idVector {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/bitwarden/crypto/kdf_argon2id_vectors.json")
	require.NoError(t, err)
	var f argon2idFixtures
	require.NoError(t, json.Unmarshal(data, &f))
	require.NotEmpty(t, f.Vectors)
	return f.Vectors[0]
}

func kdfInputFromVector(v pbkdf2Vector) ports.MasterKeyInput {
	return ports.MasterKeyInput{
		Email:    v.Email,
		Password: v.Password,
		KDF: ports.KDFConfig{
			Type:       v.KDF.Type,
			Iterations: v.KDF.Iterations,
		},
	}
}

func kdfInputFromArgon2Vector(v argon2idVector) ports.MasterKeyInput {
	return ports.MasterKeyInput{
		Email:    v.Email,
		Password: v.Password,
		KDF: ports.KDFConfig{
			Type:        v.KDF.Type,
			Iterations:  v.KDF.Iterations,
			MemoryMiB:   v.KDF.MemoryMiB,
			Parallelism: v.KDF.Parallelism,
		},
	}
}

func TestPBKDF2FixtureDerivation(t *testing.T) {
	vec := loadPBKDF2Vector(t)
	eng := NewEngine()
	input := kdfInputFromVector(vec)

	mk, err := eng.DeriveMasterKey(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, vec.DerivedKeyBytes, mk.Bytes)
}

func TestArgon2idFixtureDerivation(t *testing.T) {
	vec := loadArgon2idVector(t)
	eng := NewEngine()
	input := kdfInputFromArgon2Vector(vec)

	mk, err := eng.DeriveMasterKey(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, vec.DerivedKeyBytes, mk.Bytes)
}

func TestEmailNormalizationPBKDF2(t *testing.T) {
	vec := loadPBKDF2Vector(t)
	eng := NewEngine()

	// " TEST_KEY " should normalize to "test_key" and produce the same key.
	input := ports.MasterKeyInput{
		Email:    " TEST_KEY ",
		Password: vec.Password,
		KDF: ports.KDFConfig{
			Type:       vec.KDF.Type,
			Iterations: vec.KDF.Iterations,
		},
	}

	mk, err := eng.DeriveMasterKey(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, vec.DerivedKeyBytes, mk.Bytes)
}

func TestPBKDF2SaltNormalization(t *testing.T) {
	pass := "67t9b5g67$%Dh89n"

	eng := NewEngine()
	kdf := ports.KDFConfig{Type: "PBKDF2", Iterations: 10000}

	// Trim + lower-case should make these equivalent.
	mk1, err := eng.DeriveMasterKey(context.Background(), ports.MasterKeyInput{
		Email: "test_key", Password: pass, KDF: kdf,
	})
	require.NoError(t, err)

	mk2, err := eng.DeriveMasterKey(context.Background(), ports.MasterKeyInput{
		Email: " TEST_KEY ", Password: pass, KDF: kdf,
	})
	require.NoError(t, err)

	assert.Equal(t, mk1.Bytes, mk2.Bytes)
}

func TestPBKDF2TypeAliases(t *testing.T) {
	vec := loadPBKDF2Vector(t)
	eng := NewEngine()

	for _, kdfType := range []string{"PBKDF2", "PBKDF2_SHA256", "0"} {
		input := ports.MasterKeyInput{
			Email:    vec.Email,
			Password: vec.Password,
			KDF: ports.KDFConfig{
				Type:       kdfType,
				Iterations: vec.KDF.Iterations,
			},
		}
		mk, err := eng.DeriveMasterKey(context.Background(), input)
		require.NoError(t, err, "KDF type %q should derive the same key", kdfType)
		assert.Equal(t, vec.DerivedKeyBytes, mk.Bytes, "KDF type %q", kdfType)
	}
}

func TestArgon2idTypeAliases(t *testing.T) {
	vec := loadArgon2idVector(t)
	eng := NewEngine()

	for _, kdfType := range []string{"Argon2id", "1"} {
		input := kdfInputFromArgon2Vector(vec)
		input.KDF.Type = kdfType
		mk, err := eng.DeriveMasterKey(context.Background(), input)
		require.NoError(t, err, "KDF type %q should derive the same key", kdfType)
		assert.Equal(t, vec.DerivedKeyBytes, mk.Bytes, "KDF type %q", kdfType)
	}
}

func TestPBKDF2RejectLowIterations(t *testing.T) {
	eng := NewEngine()
	input := ports.MasterKeyInput{
		Email:    "test@example.com",
		Password: "hunter2",
		KDF:      ports.KDFConfig{Type: "PBKDF2", Iterations: 4999},
	}
	_, err := eng.DeriveMasterKey(context.Background(), input)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindValidation), "expected KindValidation, got %v", err)
}

func TestArgon2idRejectLowMemory(t *testing.T) {
	eng := NewEngine()
	input := ports.MasterKeyInput{
		Email:    "test@example.com",
		Password: "hunter2",
		KDF:      ports.KDFConfig{Type: "Argon2id", Iterations: 4, MemoryMiB: 15, Parallelism: 2},
	}
	_, err := eng.DeriveMasterKey(context.Background(), input)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindValidation), "expected KindValidation, got %v", err)
}

func TestArgon2idRejectLowIterations(t *testing.T) {
	eng := NewEngine()
	input := ports.MasterKeyInput{
		Email:    "test@example.com",
		Password: "hunter2",
		KDF:      ports.KDFConfig{Type: "Argon2id", Iterations: 1, MemoryMiB: 32, Parallelism: 2},
	}
	_, err := eng.DeriveMasterKey(context.Background(), input)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindValidation), "expected KindValidation, got %v", err)
}

func TestArgon2idRejectLowParallelism(t *testing.T) {
	eng := NewEngine()
	input := ports.MasterKeyInput{
		Email:    "test@example.com",
		Password: "hunter2",
		KDF:      ports.KDFConfig{Type: "Argon2id", Iterations: 4, MemoryMiB: 32, Parallelism: 0},
	}
	_, err := eng.DeriveMasterKey(context.Background(), input)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindValidation), "expected KindValidation, got %v", err)
}

func TestArgon2idRejectParametersAboveBitwardenMaxima(t *testing.T) {
	eng := NewEngine()
	tests := []ports.KDFConfig{
		{Type: "Argon2id", Iterations: 11, MemoryMiB: 64, Parallelism: 4},
		{Type: "Argon2id", Iterations: 3, MemoryMiB: 1025, Parallelism: 4},
		{Type: "Argon2id", Iterations: 3, MemoryMiB: 64, Parallelism: 17},
	}
	for _, kdf := range tests {
		_, err := eng.DeriveMasterKey(context.Background(), ports.MasterKeyInput{
			Email: "test@example.com", Password: "hunter2", KDF: kdf,
		})
		require.Error(t, err)
		assert.True(t, errors.Is(err, errors.KindValidation), "expected KindValidation, got %v", err)
	}
}

func TestUnknownKDFType(t *testing.T) {
	eng := NewEngine()
	input := ports.MasterKeyInput{
		Email:    "test@example.com",
		Password: "hunter2",
		KDF:      ports.KDFConfig{Type: "scrypt", Iterations: 1000},
	}
	_, err := eng.DeriveMasterKey(context.Background(), input)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto), "expected KindCrypto, got %v", err)
}

func TestContextCancellation(t *testing.T) {
	vec := loadPBKDF2Vector(t)
	eng := NewEngine()
	input := kdfInputFromVector(vec)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := eng.DeriveMasterKey(ctx, input)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestContextTimeout(t *testing.T) {
	// Use a very long PBKDF2 derivation so that a short timeout fires.
	eng := NewEngine()
	input := ports.MasterKeyInput{
		Email:    "test@example.com",
		Password: "hunter2",
		KDF:      ports.KDFConfig{Type: "PBKDF2", Iterations: 5_000_000},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	_, err := eng.DeriveMasterKey(ctx, input)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// --------------------------------------------------------------------------
// AuthHash vectors
// --------------------------------------------------------------------------

type authHashVector struct {
	Name                 string        `json:"name"`
	Password             string        `json:"password"`
	Emails               []string      `json:"emails,omitempty"`
	Email                string        `json:"email,omitempty"`
	KDF                  kdfConfigJSON `json:"kdf"`
	ServerAuthHashBase64 string        `json:"serverAuthHashBase64"`
}

type authHashFixtures struct {
	Vectors []authHashVector `json:"vectors"`
}

func loadAuthHashVectors(t *testing.T) []authHashVector {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/bitwarden/crypto/auth_hash_vectors.json")
	require.NoError(t, err)
	var f authHashFixtures
	require.NoError(t, json.Unmarshal(data, &f))
	require.NotEmpty(t, f.Vectors)
	return f.Vectors
}

func TestAuthHashPBKDF2Fixture(t *testing.T) {
	eng := NewEngine()
	for _, vec := range loadAuthHashVectors(t) {
		if vec.KDF.Type != "PBKDF2" {
			continue
		}
		for _, email := range vec.Emails {
			input := ports.MasterKeyInput{
				Email:    email,
				Password: vec.Password,
				KDF: ports.KDFConfig{
					Type:       vec.KDF.Type,
					Iterations: vec.KDF.Iterations,
				},
			}
			mk, err := eng.DeriveMasterKey(context.Background(), input)
			require.NoError(t, err)

			ah, err := eng.MakeAuthHash(context.Background(), ports.AuthHashInput{
				Password:  vec.Password,
				MasterKey: mk,
			})
			require.NoError(t, err)
			assert.Equal(t, ports.AuthHash(vec.ServerAuthHashBase64), ah)
		}
	}
}

func TestAuthHashArgon2idFixture(t *testing.T) {
	eng := NewEngine()
	for _, vec := range loadAuthHashVectors(t) {
		if vec.KDF.Type != "Argon2id" {
			continue
		}
		input := ports.MasterKeyInput{
			Email:    vec.Email,
			Password: vec.Password,
			KDF: ports.KDFConfig{
				Type:        vec.KDF.Type,
				Iterations:  vec.KDF.Iterations,
				MemoryMiB:   vec.KDF.MemoryMiB,
				Parallelism: vec.KDF.Parallelism,
			},
		}
		mk, err := eng.DeriveMasterKey(context.Background(), input)
		require.NoError(t, err)

		ah, err := eng.MakeAuthHash(context.Background(), ports.AuthHashInput{
			Password:  vec.Password,
			MasterKey: mk,
		})
		require.NoError(t, err)
		assert.Equal(t, ports.AuthHash(vec.ServerAuthHashBase64), ah)
	}
}

func TestAuthHashInvalidKeyLength(t *testing.T) {
	eng := NewEngine()
	_, err := eng.MakeAuthHash(context.Background(), ports.AuthHashInput{
		Password:  "test",
		MasterKey: ports.MasterKey{Bytes: make([]byte, 31)},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindValidation))

	_, err = eng.MakeAuthHash(context.Background(), ports.AuthHashInput{
		Password:  "test",
		MasterKey: ports.MasterKey{Bytes: make([]byte, 33)},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindValidation))
}

func TestAuthHashContextCancellation(t *testing.T) {
	eng := NewEngine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := eng.MakeAuthHash(ctx, ports.AuthHashInput{
		Password:  "test",
		MasterKey: ports.MasterKey{Bytes: make([]byte, 32)},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

// --------------------------------------------------------------------------
// UserKey vectors
// --------------------------------------------------------------------------

type userKeyVector struct {
	Name               string        `json:"name"`
	Password           string        `json:"password"`
	Email              string        `json:"email"`
	KDF                kdfConfigJSON `json:"kdf"`
	EncryptedUserKey   string        `json:"encryptedUserKey"`
	UserKeyEncKeyBytes []byte        `json:"userKeyEncKeyBytes"`
	UserKeyMacKeyBytes []byte        `json:"userKeyMacKeyBytes"`
}

type userKeyFixtures struct {
	Vectors []userKeyVector `json:"vectors"`
}

func loadUserKeyVectors(t *testing.T) []userKeyVector {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/bitwarden/crypto/user_key_vectors.json")
	require.NoError(t, err)
	var f userKeyFixtures
	require.NoError(t, json.Unmarshal(data, &f))
	require.NotEmpty(t, f.Vectors)
	return f.Vectors
}

func TestUnlockUserKeyLegacyFixture(t *testing.T) {
	eng := NewEngine()
	for _, vec := range loadUserKeyVectors(t) {
		input := ports.MasterKeyInput{
			Email:    vec.Email,
			Password: vec.Password,
			KDF: ports.KDFConfig{
				Type:       vec.KDF.Type,
				Iterations: vec.KDF.Iterations,
			},
		}
		mk, err := eng.DeriveMasterKey(context.Background(), input)
		require.NoError(t, err)

		uk, err := eng.UnlockUserKey(context.Background(), ports.UserKeyInput{
			MasterKey:        mk,
			EncryptedUserKey: vec.EncryptedUserKey,
		})
		require.NoError(t, err)

		expected := append(vec.UserKeyEncKeyBytes, vec.UserKeyMacKeyBytes...)
		assert.Equal(t, expected, uk.Bytes)
	}
}

func TestUnlockUserKeyInvalidKeyLength(t *testing.T) {
	eng := NewEngine()

	_, err := eng.UnlockUserKey(context.Background(), ports.UserKeyInput{
		MasterKey:        ports.MasterKey{Bytes: make([]byte, 31)},
		EncryptedUserKey: "0.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAA",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto))
}

func TestUnlockUserKeyInvalidEncString(t *testing.T) {
	eng := NewEngine()

	// Missing type prefix.
	_, err := eng.UnlockUserKey(context.Background(), ports.UserKeyInput{
		MasterKey:        ports.MasterKey{Bytes: make([]byte, 32)},
		EncryptedUserKey: "not-an-enc-string",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto))

	// Unknown type.
	_, err = eng.UnlockUserKey(context.Background(), ports.UserKeyInput{
		MasterKey:        ports.MasterKey{Bytes: make([]byte, 32)},
		EncryptedUserKey: "9.xxx|yyy",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto))
}

func TestUnlockUserKeyContextCancellation(t *testing.T) {
	eng := NewEngine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := eng.UnlockUserKey(ctx, ports.UserKeyInput{
		MasterKey:        ports.MasterKey{Bytes: make([]byte, 32)},
		EncryptedUserKey: "0.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAA",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestUnlockUserKeyType2MACMismatch(t *testing.T) {
	eng := NewEngine()

	// Build a valid type-2 encrypted payload deterministically, then mutate the MAC.
	masterKey := ports.MasterKey{Bytes: make([]byte, 32)}
	for i := range masterKey.Bytes {
		masterKey.Bytes[i] = byte(i)
	}

	// Stretch key: encKey, macKey.
	encKey, macKey := stretchKey(masterKey.Bytes)

	// IV, plaintext, encrypt.
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(16 - i)
	}
	plaintext := []byte("hello world")

	ciphertext, err := aes256cbcEncrypt(encKey[:], iv, plaintext)
	require.NoError(t, err)

	// Compute MAC = HMAC-SHA256(macKey[:], iv || ciphertext).
	mac := computeMac(macKey[:], iv, ciphertext)

	// Format as "2.<iv_b64>|<ct_b64>|<mac_b64>".
	ivB64 := base64.StdEncoding.EncodeToString(iv)
	ctB64 := base64.StdEncoding.EncodeToString(ciphertext)
	_ = base64.StdEncoding.EncodeToString(mac) // valid mac for reference

	// Corrupt the MAC: flip the first byte.
	macCorrupted := make([]byte, len(mac))
	copy(macCorrupted, mac)
	macCorrupted[0] ^= 0xff
	macCorruptedB64 := base64.StdEncoding.EncodeToString(macCorrupted)

	badEncString := "2." + ivB64 + "|" + ctB64 + "|" + macCorruptedB64

	_, err = eng.UnlockUserKey(context.Background(), ports.UserKeyInput{
		MasterKey:        masterKey,
		EncryptedUserKey: badEncString,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindCrypto))
}
