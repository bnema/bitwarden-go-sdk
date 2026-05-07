package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	pbkdf2MinIterations = 5000

	argon2idMinMemory     = 16 // MiB
	argon2idMaxMemory     = 1024
	argon2idMinIterations = 2
	argon2idMaxIterations = 10
	argon2idMinParallel   = 1
	argon2idMaxParallel   = 16
)

// Engine implements ports.CryptoEngine for KDF derivation, auth hash
// computation, and user key unwrap. Cipher encrypt/decrypt and attachment
// key operations are deferred to later phases.
type Engine struct{}

// NewEngine returns a new crypto Engine.
func NewEngine() *Engine {
	return &Engine{}
}

// DeriveMasterKey derives a 32-byte master key from the given input according
// to the Bitwarden KDF specification.
func (e *Engine) DeriveMasterKey(ctx context.Context, input ports.MasterKeyInput) (ports.MasterKey, error) {
	// Normalize email: trim + lower-case becomes the salt.
	salt := strings.ToLower(strings.TrimSpace(input.Email))

	switch normalizeKDFType(input.KDF.Type) {
	case kdfTypePBKDF2:
		return e.derivePBKDF2(ctx, salt, input.Password, input.KDF.Iterations)
	case kdfTypeArgon2id:
		return e.deriveArgon2id(ctx, salt, input.Password, input.KDF)
	default:
		return ports.MasterKey{}, &errors.Error{
			Kind:    errors.KindCrypto,
			Op:      "crypto.DeriveMasterKey",
			Code:    "unsupported_kdf",
			Message: "unsupported KDF type",
		}
	}
}

func (e *Engine) derivePBKDF2(ctx context.Context, salt, password string, iterations int) (ports.MasterKey, error) {
	if iterations < pbkdf2MinIterations {
		return ports.MasterKey{}, &errors.Error{
			Kind:    errors.KindValidation,
			Op:      "crypto.derivePBKDF2",
			Code:    "insufficient_kdf_iterations",
			Message: fmt.Sprintf("PBKDF2 iterations must be at least %d", pbkdf2MinIterations),
		}
	}

	// Derive in chunks so context cancellation is checked frequently enough.
	keyLen := 32
	result := make(chan []byte, 1)
	errCh := make(chan error, 1)

	go func() {
		// Check context before starting heavy derivation.
		select {
		case <-ctx.Done():
			errCh <- ctx.Err()
			return
		default:
		}
		dk := pbkdf2.Key([]byte(password), []byte(salt), iterations, keyLen, sha256.New)
		result <- dk
	}()

	select {
	case <-ctx.Done():
		return ports.MasterKey{}, ctx.Err()
	case err := <-errCh:
		return ports.MasterKey{}, err
	case dk := <-result:
		return ports.MasterKey{Bytes: dk}, nil
	}
}

func (e *Engine) deriveArgon2id(ctx context.Context, salt, password string, kdf ports.KDFConfig) (ports.MasterKey, error) {
	memoryMiB := kdf.MemoryMiB
	iterations := kdf.Iterations
	parallelism := kdf.Parallelism

	if memoryMiB < argon2idMinMemory || memoryMiB > argon2idMaxMemory ||
		iterations < argon2idMinIterations || iterations > argon2idMaxIterations ||
		parallelism < argon2idMinParallel || parallelism > argon2idMaxParallel {
		return ports.MasterKey{}, &errors.Error{
			Kind: errors.KindValidation,
			Op:   "crypto.deriveArgon2id",
			Code: "invalid_kdf_parameters",
			Message: fmt.Sprintf("Argon2id requires memory %d-%dMiB, iterations %d-%d, parallelism %d-%d",
				argon2idMinMemory, argon2idMaxMemory,
				argon2idMinIterations, argon2idMaxIterations,
				argon2idMinParallel, argon2idMaxParallel),
		}
	}

	// Per sdk-internal: salt is SHA256(normalized email).
	saltHash := sha256.Sum256([]byte(salt))
	argonSalt := saltHash[:]

	memoryKiB := uint32(memoryMiB) * 1024

	keyLen := 32
	result := make(chan []byte, 1)
	errCh := make(chan error, 1)

	go func() {
		select {
		case <-ctx.Done():
			errCh <- ctx.Err()
			return
		default:
		}
		dk := argon2.IDKey([]byte(password), argonSalt, uint32(iterations), memoryKiB, uint8(parallelism), uint32(keyLen))
		result <- dk
	}()

	select {
	case <-ctx.Done():
		return ports.MasterKey{}, ctx.Err()
	case err := <-errCh:
		return ports.MasterKey{}, err
	case dk := <-result:
		return ports.MasterKey{Bytes: dk}, nil
	}
}

type kdfKind int

const (
	kdfTypePBKDF2 kdfKind = iota
	kdfTypeArgon2id
	kdfTypeUnknown
)

func normalizeKDFType(t string) kdfKind {
	switch strings.TrimSpace(t) {
	case "0", "PBKDF2_SHA256", "PBKDF2":
		return kdfTypePBKDF2
	case "1", "Argon2id":
		return kdfTypeArgon2id
	default:
		return kdfTypeUnknown
	}
}

// MakeAuthHash computes the server authentication hash from the master key
// and password. It uses PBKDF2-HMAC-SHA256 with the password bytes as salt,
// 1 iteration, and 32-byte output, then encodes as standard base64.
func (e *Engine) MakeAuthHash(ctx context.Context, input ports.AuthHashInput) (ports.AuthHash, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(input.MasterKey.Bytes) != 32 {
		return "", &errors.Error{
			Kind:    errors.KindValidation,
			Op:      "crypto.MakeAuthHash",
			Code:    "invalid_key_length",
			Message: "master key must be 32 bytes",
		}
	}
	dk := pbkdf2.Key(input.MasterKey.Bytes, []byte(input.Password), 1, 32, sha256.New)
	return ports.AuthHash(base64.StdEncoding.EncodeToString(dk)), nil
}

// UnlockUserKey decrypts an encrypted user key (EncString type 0 or 2)
// using the master key and returns the plaintext user key.
func (e *Engine) UnlockUserKey(ctx context.Context, input ports.UserKeyInput) (ports.UserKey, error) {
	if err := ctx.Err(); err != nil {
		return ports.UserKey{}, err
	}
	if len(input.MasterKey.Bytes) != 32 {
		return ports.UserKey{}, &errors.Error{
			Kind:    errors.KindCrypto,
			Op:      "crypto.UnlockUserKey",
			Code:    "invalid_key_length",
			Message: "master key must be 32 bytes",
		}
	}

	encType, iv, ct, mac, err := parseEncString(input.EncryptedUserKey)
	if err != nil {
		return ports.UserKey{}, &errors.Error{
			Kind:    errors.KindCrypto,
			Op:      "crypto.UnlockUserKey",
			Code:    "malformed_enc_string",
			Message: "invalid encrypted user key format",
		}
	}

	var plaintext []byte
	switch encType {
	case 0:
		// Legacy: AES-256-CBC with master key as AES key, no MAC.
		decrypted, decErr := aes256cbcDecrypt(input.MasterKey.Bytes, iv, ct)
		if decErr != nil {
			return ports.UserKey{}, &errors.Error{
				Kind:    errors.KindCrypto,
				Op:      "crypto.UnlockUserKey",
				Code:    "decryption_failed",
				Message: "failed to decrypt user key",
			}
		}
		unpadded, unpadErr := pkcs7Unpad(decrypted)
		if unpadErr != nil {
			return ports.UserKey{}, &errors.Error{
				Kind:    errors.KindCrypto,
				Op:      "crypto.UnlockUserKey",
				Code:    "invalid_padding",
				Message: "user key padding invalid",
			}
		}
		plaintext = unpadded

	case 2:
		// Modern: stretch master key with HKDF, verify MAC, then decrypt.
		encKey, macKey := stretchKey(input.MasterKey.Bytes)
		expectedMAC := computeMac(macKey[:], iv, ct)
		if !constantTimeEq(expectedMAC, mac) {
			return ports.UserKey{}, &errors.Error{
				Kind:    errors.KindCrypto,
				Op:      "crypto.UnlockUserKey",
				Code:    "mac_mismatch",
				Message: "user key MAC verification failed",
			}
		}
		decrypted, decErr := aes256cbcDecrypt(encKey[:], iv, ct)
		if decErr != nil {
			return ports.UserKey{}, &errors.Error{
				Kind:    errors.KindCrypto,
				Op:      "crypto.UnlockUserKey",
				Code:    "decryption_failed",
				Message: "failed to decrypt user key",
			}
		}
		unpadded, unpadErr := pkcs7Unpad(decrypted)
		if unpadErr != nil {
			return ports.UserKey{}, &errors.Error{
				Kind:    errors.KindCrypto,
				Op:      "crypto.UnlockUserKey",
				Code:    "invalid_padding",
				Message: "user key padding invalid",
			}
		}
		plaintext = unpadded
	default:
		return ports.UserKey{}, &errors.Error{
			Kind:    errors.KindCrypto,
			Op:      "crypto.UnlockUserKey",
			Code:    "unsupported_enc_type",
			Message: fmt.Sprintf("unsupported encryption type %d", encType),
		}
	}

	return ports.UserKey{Bytes: plaintext}, nil
}

// EncryptCipher encrypts a Cipher into an EncryptedCipher using the user key.
// The user key must be 64 bytes (first 32 = enc key, next 32 = mac key).
// Bitwarden composite cipher encryption encrypts payload strings as type-2
// EncStrings while preserving metadata such as type, favorite, URI match, and
// custom-field type/linked ID.
func (e *Engine) EncryptCipher(ctx context.Context, key ports.UserKey, cipher ports.Cipher) (ports.EncryptedCipher, error) {
	if err := ctx.Err(); err != nil {
		return ports.EncryptedCipher{}, err
	}
	if len(key.Bytes) != 64 {
		return ports.EncryptedCipher{}, &errors.Error{
			Kind:    errors.KindValidation,
			Op:      "crypto.EncryptCipher",
			Code:    "invalid_key_length",
			Message: "user key must be 64 bytes",
		}
	}

	if cipher.Type == 0 {
		return ports.EncryptedCipher{}, &errors.Error{
			Kind:    errors.KindValidation,
			Op:      "crypto.EncryptCipher",
			Code:    "missing_cipher_type",
			Message: "cipher type must be non-zero",
		}
	}
	enc := ports.EncryptedCipher{ID: cipher.ID, Type: cipher.Type, Favorite: cipher.Favorite, FolderID: cipher.FolderID}
	var err error
	if enc.Name, err = encryptCipherString(key.Bytes, cipher.Name); err != nil {
		return ports.EncryptedCipher{}, err
	}
	if enc.Notes, err = encryptCipherString(key.Bytes, cipher.Notes); err != nil {
		return ports.EncryptedCipher{}, err
	}
	if enc.Username, err = encryptCipherString(key.Bytes, cipher.Username); err != nil {
		return ports.EncryptedCipher{}, err
	}
	if enc.Password, err = encryptCipherString(key.Bytes, cipher.Password); err != nil {
		return ports.EncryptedCipher{}, err
	}
	if enc.URI, err = encryptCipherString(key.Bytes, cipher.URI); err != nil {
		return ports.EncryptedCipher{}, err
	}
	if cipher.Login != nil {
		login := &ports.EncryptedLoginCipher{}
		if login.Username, err = encryptCipherString(key.Bytes, cipher.Login.Username); err != nil {
			return ports.EncryptedCipher{}, err
		}
		if login.Password, err = encryptCipherString(key.Bytes, cipher.Login.Password); err != nil {
			return ports.EncryptedCipher{}, err
		}
		if login.TOTP, err = encryptCipherString(key.Bytes, cipher.Login.TOTP); err != nil {
			return ports.EncryptedCipher{}, err
		}
		login.URIs = make([]ports.EncryptedLoginURI, len(cipher.Login.URIs))
		for i, uri := range cipher.Login.URIs {
			login.URIs[i].Match = uri.Match
			if login.URIs[i].URI, err = encryptCipherString(key.Bytes, uri.URI); err != nil {
				return ports.EncryptedCipher{}, err
			}
			if login.URIs[i].URIChecksum, err = encryptCipherString(key.Bytes, uri.URIChecksum); err != nil {
				return ports.EncryptedCipher{}, err
			}
		}
		enc.Login = login
	}
	if cipher.SecureNote != nil {
		enc.SecureNote = &ports.EncryptedSecureNoteCipher{Type: cipher.SecureNote.Type}
	}
	if cipher.Card != nil {
		card := &ports.EncryptedCardCipher{}
		if card.CardholderName, err = encryptCipherString(key.Bytes, cipher.Card.CardholderName); err != nil {
			return ports.EncryptedCipher{}, err
		}
		if card.Brand, err = encryptCipherString(key.Bytes, cipher.Card.Brand); err != nil {
			return ports.EncryptedCipher{}, err
		}
		if card.Number, err = encryptCipherString(key.Bytes, cipher.Card.Number); err != nil {
			return ports.EncryptedCipher{}, err
		}
		if card.ExpMonth, err = encryptCipherString(key.Bytes, cipher.Card.ExpMonth); err != nil {
			return ports.EncryptedCipher{}, err
		}
		if card.ExpYear, err = encryptCipherString(key.Bytes, cipher.Card.ExpYear); err != nil {
			return ports.EncryptedCipher{}, err
		}
		if card.Code, err = encryptCipherString(key.Bytes, cipher.Card.Code); err != nil {
			return ports.EncryptedCipher{}, err
		}
		enc.Card = card
	}
	if cipher.Identity != nil {
		identity := &ports.EncryptedIdentityCipher{}
		if err = encryptIdentity(key.Bytes, cipher.Identity, identity); err != nil {
			return ports.EncryptedCipher{}, err
		}
		enc.Identity = identity
	}
	if cipher.Fields != nil {
		enc.Fields = make([]ports.EncryptedCipherField, len(cipher.Fields))
		for i, field := range cipher.Fields {
			enc.Fields[i].Type = field.Type
			enc.Fields[i].LinkedID = field.LinkedID
			if enc.Fields[i].Name, err = encryptCipherString(key.Bytes, field.Name); err != nil {
				return ports.EncryptedCipher{}, err
			}
			if enc.Fields[i].Value, err = encryptCipherString(key.Bytes, field.Value); err != nil {
				return ports.EncryptedCipher{}, err
			}
		}
	}
	return enc, nil
}

// DecryptCipher decrypts an EncryptedCipher back into a Cipher using the user key.
// Any decryption failure returns KindCrypto without leaking plaintext or ciphertext.
func (e *Engine) DecryptCipher(ctx context.Context, key ports.UserKey, cipher ports.EncryptedCipher) (ports.Cipher, error) {
	if err := ctx.Err(); err != nil {
		return ports.Cipher{}, err
	}
	if len(key.Bytes) != 64 {
		return ports.Cipher{}, &errors.Error{
			Kind:    errors.KindValidation,
			Op:      "crypto.DecryptCipher",
			Code:    "invalid_key_length",
			Message: "user key must be 64 bytes",
		}
	}

	dec := ports.Cipher{ID: cipher.ID, Type: cipher.Type, Favorite: cipher.Favorite, FolderID: cipher.FolderID}
	var err error
	if dec.Name, err = decryptCipherString(key.Bytes, cipher.Name); err != nil {
		return ports.Cipher{}, err
	}
	if dec.Notes, err = decryptCipherString(key.Bytes, cipher.Notes); err != nil {
		return ports.Cipher{}, err
	}
	if dec.Username, err = decryptCipherString(key.Bytes, cipher.Username); err != nil {
		return ports.Cipher{}, err
	}
	if dec.Password, err = decryptCipherString(key.Bytes, cipher.Password); err != nil {
		return ports.Cipher{}, err
	}
	if dec.URI, err = decryptCipherString(key.Bytes, cipher.URI); err != nil {
		return ports.Cipher{}, err
	}
	if cipher.Login != nil {
		login := &ports.LoginCipher{}
		if login.Username, err = decryptCipherString(key.Bytes, cipher.Login.Username); err != nil {
			return ports.Cipher{}, err
		}
		if login.Password, err = decryptCipherString(key.Bytes, cipher.Login.Password); err != nil {
			return ports.Cipher{}, err
		}
		if login.TOTP, err = decryptCipherString(key.Bytes, cipher.Login.TOTP); err != nil {
			return ports.Cipher{}, err
		}
		login.URIs = make([]ports.LoginURI, len(cipher.Login.URIs))
		for i, uri := range cipher.Login.URIs {
			login.URIs[i].Match = uri.Match
			if login.URIs[i].URI, err = decryptCipherString(key.Bytes, uri.URI); err != nil {
				return ports.Cipher{}, err
			}
			if login.URIs[i].URIChecksum, err = decryptCipherString(key.Bytes, uri.URIChecksum); err != nil {
				return ports.Cipher{}, err
			}
		}
		dec.Login = login
	}
	if cipher.SecureNote != nil {
		dec.SecureNote = &ports.SecureNoteCipher{Type: cipher.SecureNote.Type}
	}
	if cipher.Card != nil {
		card := &ports.CardCipher{}
		if card.CardholderName, err = decryptCipherString(key.Bytes, cipher.Card.CardholderName); err != nil {
			return ports.Cipher{}, err
		}
		if card.Brand, err = decryptCipherString(key.Bytes, cipher.Card.Brand); err != nil {
			return ports.Cipher{}, err
		}
		if card.Number, err = decryptCipherString(key.Bytes, cipher.Card.Number); err != nil {
			return ports.Cipher{}, err
		}
		if card.ExpMonth, err = decryptCipherString(key.Bytes, cipher.Card.ExpMonth); err != nil {
			return ports.Cipher{}, err
		}
		if card.ExpYear, err = decryptCipherString(key.Bytes, cipher.Card.ExpYear); err != nil {
			return ports.Cipher{}, err
		}
		if card.Code, err = decryptCipherString(key.Bytes, cipher.Card.Code); err != nil {
			return ports.Cipher{}, err
		}
		dec.Card = card
	}
	if cipher.Identity != nil {
		identity := &ports.IdentityCipher{}
		if err = decryptIdentity(key.Bytes, cipher.Identity, identity); err != nil {
			return ports.Cipher{}, err
		}
		dec.Identity = identity
	}
	if cipher.Fields != nil {
		dec.Fields = make([]ports.CipherField, len(cipher.Fields))
		for i, field := range cipher.Fields {
			dec.Fields[i].Type = field.Type
			dec.Fields[i].LinkedID = field.LinkedID
			if dec.Fields[i].Name, err = decryptCipherString(key.Bytes, field.Name); err != nil {
				return ports.Cipher{}, err
			}
			if dec.Fields[i].Value, err = decryptCipherString(key.Bytes, field.Value); err != nil {
				return ports.Cipher{}, err
			}
		}
	}
	return dec, nil
}

// EncryptFolderName encrypts a folder name using the user key and returns a
// type 2 EncString.
func (e *Engine) EncryptFolderName(ctx context.Context, key ports.UserKey, name string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(key.Bytes) != 64 {
		return "", &errors.Error{
			Kind:    errors.KindValidation,
			Op:      "crypto.EncryptFolderName",
			Code:    "invalid_key_length",
			Message: "user key must be 64 bytes",
		}
	}

	encrypted, err := encryptType2(key.Bytes, name)
	if err != nil {
		return "", &errors.Error{
			Kind:    errors.KindCrypto,
			Op:      "crypto.EncryptFolderName",
			Code:    "encryption_failed",
			Message: "failed to encrypt folder name",
		}
	}

	return encrypted, nil
}

// DecryptFolderName decrypts a type 2 EncString folder name using the user key.
func (e *Engine) DecryptFolderName(ctx context.Context, key ports.UserKey, encryptedName string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(key.Bytes) != 64 {
		return "", &errors.Error{
			Kind:    errors.KindValidation,
			Op:      "crypto.DecryptFolderName",
			Code:    "invalid_key_length",
			Message: "user key must be 64 bytes",
		}
	}

	decrypted, err := decryptType2(key.Bytes, encryptedName)
	if err != nil {
		return "", &errors.Error{
			Kind:    errors.KindCrypto,
			Op:      "crypto.DecryptFolderName",
			Code:    "decryption_failed",
			Message: "failed to decrypt folder name",
		}
	}

	return decrypted, nil
}

var _ ports.CryptoEngine = (*Engine)(nil)
