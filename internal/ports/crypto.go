package ports

import "context"

// CryptoEngine defines scaffold cryptographic operations.
type CryptoEngine interface {
	DeriveMasterKey(ctx context.Context, input MasterKeyInput) (MasterKey, error)
	MakeAuthHash(ctx context.Context, input AuthHashInput) (AuthHash, error)
	UnlockUserKey(ctx context.Context, input UserKeyInput) (UserKey, error)
	DecryptCipher(ctx context.Context, key UserKey, cipher EncryptedCipher) (Cipher, error)
	EncryptCipher(ctx context.Context, key UserKey, cipher Cipher) (EncryptedCipher, error)
	DecryptAttachmentKey(ctx context.Context, key UserKey, attachment EncryptedAttachment) (AttachmentKey, error)
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

// Cipher contains scaffold decrypted cipher fields.
type Cipher struct {
	ID       string
	Name     string
	Username string
	Password string
	URI      string
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
