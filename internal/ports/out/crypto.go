package out

import "context"

type CryptoEngine interface {
	DeriveMasterKey(ctx context.Context, input MasterKeyInput) (MasterKey, error)
	MakeAuthHash(ctx context.Context, input AuthHashInput) (AuthHash, error)
	UnlockUserKey(ctx context.Context, input UserKeyInput) (UserKey, error)
	DecryptCipher(ctx context.Context, key UserKey, cipher EncryptedCipher) (Cipher, error)
	EncryptCipher(ctx context.Context, key UserKey, cipher Cipher) (EncryptedCipher, error)
	DecryptAttachmentKey(ctx context.Context, key UserKey, attachment EncryptedAttachment) (AttachmentKey, error)
}

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

type AuthHashInput struct {
	Password  string
	MasterKey MasterKey
}

type AuthHash string

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

type Cipher struct {
	ID       string
	Name     string
	Username string
	Password string
	URI      string
}

type EncryptedAttachment struct {
	ID  string
	Key string
}

// AttachmentKey is a scaffold type. The attachments implementation plan must
// revisit this representation before real attachment key material is processed.
type AttachmentKey struct {
	Bytes []byte
}
