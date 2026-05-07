package ports

import (
	"context"
	"io"
)

// CryptoEngine defines scaffold cryptographic operations.
type CryptoEngine interface {
	DeriveMasterKey(ctx context.Context, input MasterKeyInput) (MasterKey, error)
	MakeAuthHash(ctx context.Context, input AuthHashInput) (AuthHash, error)
	UnlockUserKey(ctx context.Context, input UserKeyInput) (UserKey, error)
	DecryptCipher(ctx context.Context, key UserKey, cipher EncryptedCipher) (Cipher, error)
	EncryptCipher(ctx context.Context, key UserKey, cipher Cipher) (EncryptedCipher, error)
	WrapAttachmentKey(ctx context.Context, key UserKey, attachmentKey AttachmentKey) (string, error)
	DecryptAttachmentKey(ctx context.Context, key UserKey, attachment EncryptedAttachment) (AttachmentKey, error)
	EncryptAttachment(ctx context.Context, key AttachmentKey, src io.Reader, dst io.Writer) error
	DecryptAttachment(ctx context.Context, key AttachmentKey, src io.Reader, dst io.Writer) error
	EncryptFolderName(ctx context.Context, key UserKey, name string) (string, error)
	DecryptFolderName(ctx context.Context, key UserKey, encryptedName string) (string, error)
}

// MasterKeyInput contains scaffold master-key derivation inputs.
type MasterKeyInput struct {
	Email    string
	Password string
	KDF      KDFConfig
}

// MasterKey is a scaffold type. The crypto implementation plan must replace or
// wrap this representation with secret-memory-safe handling before real key
// material is processed.
type MasterKey struct {
	Bytes []byte
}

// Close zeros master-key bytes. It is idempotent.
func (k *MasterKey) Close() {
	for i := range k.Bytes {
		k.Bytes[i] = 0
	}
	k.Bytes = nil
}

// AuthHashInput contains scaffold auth-hash inputs.
type AuthHashInput struct {
	Password  string
	MasterKey MasterKey
}

// AuthHash contains a scaffold authentication hash.
type AuthHash string

// UserKeyInput contains scaffold user-key unwrap inputs.
type UserKeyInput struct {
	MasterKey        MasterKey
	EncryptedUserKey string
}

// UserKey is a scaffold type. The crypto implementation plan must replace or
// wrap this representation with secret-memory-safe handling before real key
// material is processed.
type UserKey struct {
	Bytes []byte
}

// Close zeros user-key bytes. It is idempotent.
func (k *UserKey) Close() {
	for i := range k.Bytes {
		k.Bytes[i] = 0
	}
	k.Bytes = nil
}

// Cipher contains decrypted cipher fields covered by the v0.1.0 crypto
// adapter. Composite encryption mirrors Bitwarden: only string payload fields
// become EncStrings; metadata such as Type, Favorite, URI Match, and field
// Type/LinkedID remains plaintext.
type Cipher struct {
	ID       string
	Type     int
	Name     string
	Notes    string
	Favorite bool
	FolderID string

	// Legacy login scaffold fields kept until later public API phases finish
	// replacing direct fields with Login.
	Username string
	Password string
	URI      string

	Login      *LoginCipher
	SecureNote *SecureNoteCipher
	Card       *CardCipher
	Identity   *IdentityCipher
	Fields     []CipherField
}

// LoginCipher contains decrypted login-specific cipher fields.
type LoginCipher struct {
	Username string
	Password string
	TOTP     string
	URIs     []LoginURI
}

// LoginURI contains a decrypted login URI and plaintext match metadata.
type LoginURI struct {
	URI         string
	Match       int
	URIChecksum string
}

// SecureNoteCipher contains secure-note metadata; note text lives on Cipher.Notes.
type SecureNoteCipher struct {
	Type int
}

// CardCipher contains decrypted payment-card fields.
type CardCipher struct {
	CardholderName string
	Brand          string
	Number         string
	ExpMonth       string
	ExpYear        string
	Code           string
}

// IdentityCipher contains decrypted identity-profile fields.
type IdentityCipher struct {
	Title          string
	FirstName      string
	MiddleName     string
	LastName       string
	Address1       string
	Address2       string
	Address3       string
	City           string
	State          string
	PostalCode     string
	Country        string
	Company        string
	Email          string
	Phone          string
	SSN            string
	Username       string
	PassportNumber string
	LicenseNumber  string
}

// CipherField contains a decrypted custom field and plaintext metadata.
type CipherField struct {
	Name     string
	Value    string
	Type     int
	LinkedID int
}

// EncryptedAttachment contains scaffold encrypted attachment fields.
type EncryptedAttachment struct {
	ID  string
	Key string
}

// AttachmentKey is a scaffold type. The attachments implementation plan must
// revisit this representation before real attachment key material is processed.
type AttachmentKey struct {
	Bytes []byte
}

// Close zeros attachment-key bytes. It is idempotent.
func (k *AttachmentKey) Close() {
	for i := range k.Bytes {
		k.Bytes[i] = 0
	}
	k.Bytes = nil
}
