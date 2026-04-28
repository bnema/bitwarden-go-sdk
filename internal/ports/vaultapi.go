package ports

import (
	"context"
	"io"
)

// APIClient defines scaffold Bitwarden API operations.
// Types in this package are compile-safe scaffold contracts. The source-mapping
// plan must verify and adjust field names before real Bitwarden behavior is added.
type APIClient interface {
	Config(ctx context.Context) (ServerConfig, error)
	AccountProfile(ctx context.Context) (AccountProfile, error)
	Subscription(ctx context.Context) (Subscription, error)
	Sync(ctx context.Context, opts SyncOptions) (SyncResult, error)
	CreateCipher(ctx context.Context, cipher EncryptedCipher) (EncryptedCipher, error)
	UpdateCipher(ctx context.Context, id string, cipher EncryptedCipher) (EncryptedCipher, error)
	DeleteCipher(ctx context.Context, id string) error
	TrashCipher(ctx context.Context, id string) error
	RestoreCipher(ctx context.Context, id string) (EncryptedCipher, error)

	GetAttachment(ctx context.Context, cipherID, attachmentID string) (EncryptedAttachmentMetadata, error)
	InitAttachmentUpload(ctx context.Context, req AttachmentUploadRequest) (AttachmentUploadResponse, error)
	UploadAttachmentDirect(ctx context.Context, cipherID, attachmentID string, content io.Reader) error
	UploadAttachmentExternal(ctx context.Context, uploadURL string, content io.Reader) error
	RenewAttachmentUploadURL(ctx context.Context, cipherID, attachmentID string) (AttachmentUploadResponse, error)
	DownloadAttachment(ctx context.Context, url string) (io.ReadCloser, error)
	DeleteAttachment(ctx context.Context, cipherID, attachmentID string) (EncryptedCipher, error)

	ListFolders(ctx context.Context) ([]EncryptedFolder, error)
	CreateFolder(ctx context.Context, folder EncryptedFolder) (EncryptedFolder, error)
	UpdateFolder(ctx context.Context, id string, folder EncryptedFolder) (EncryptedFolder, error)
	DeleteFolder(ctx context.Context, id string) error
}

// ServerConfig contains scaffold server configuration fields.
type ServerConfig struct {
	Version      string
	FeatureFlags map[string]bool
	ServerName   string
}

// AccountProfile contains scaffold account profile fields.
type AccountProfile struct {
	ID                      string
	Email                   string
	Name                    string
	EmailVerified           bool
	Premium                 bool
	PremiumFromOrganization bool
	Culture                 string
	TwoFactorEnabled        bool
	ForcePasswordReset      bool
	UsesKeyConnector        bool
	VerifyDevices           bool
}

// Subscription contains scaffold subscription fields.
type Subscription struct {
	Plan         string
	IsPremium    bool
	StorageName  string
	StorageGB    int
	MaxStorageGB int
}

// SyncOptions contains scaffold sync request options.
type SyncOptions struct {
	ExcludeDomains bool
}

// SyncResult contains scaffold sync response fields.
type SyncResult struct {
	Profile AccountProfile
	Folders []EncryptedFolder
	Ciphers []EncryptedCipher
}

// EncryptedFolder contains scaffold encrypted folder fields.
type EncryptedFolder struct {
	ID   string
	Name string
}

// EncryptedCipher contains encrypted cipher fields.
// Encrypted string fields hold Bitwarden type-2 EncStrings. Plain metadata
// fields such as Type, Favorite, URI Match, and field Type/LinkedID are not
// encrypted by Bitwarden's composite cipher format.
type EncryptedCipher struct {
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

	Login      *EncryptedLoginCipher
	SecureNote *EncryptedSecureNoteCipher
	Card       *EncryptedCardCipher
	Identity   *EncryptedIdentityCipher
	Fields     []EncryptedCipherField
}

// EncryptedLoginCipher contains encrypted login-specific cipher fields.
type EncryptedLoginCipher struct {
	Username string
	Password string
	TOTP     string
	URIs     []EncryptedLoginURI
}

// EncryptedLoginURI contains encrypted URI fields and plaintext match metadata.
type EncryptedLoginURI struct {
	URI         string
	Match       int
	URIChecksum string
}

// EncryptedSecureNoteCipher contains secure-note metadata.
type EncryptedSecureNoteCipher struct {
	Type int
}

// EncryptedCardCipher contains encrypted payment-card fields.
type EncryptedCardCipher struct {
	CardholderName string
	Brand          string
	Number         string
	ExpMonth       string
	ExpYear        string
	Code           string
}

// EncryptedIdentityCipher contains encrypted identity-profile fields.
type EncryptedIdentityCipher struct {
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

// EncryptedAttachmentMetadata contains scaffold encrypted attachment metadata fields.
type EncryptedAttachmentMetadata struct {
	ID       string
	CipherID string
	FileName string
	Key      string
	Size     int64
	SizeName string
	URL      string
}

// AttachmentUploadRequest contains scaffold attachment upload request fields.
type AttachmentUploadRequest struct {
	CipherID string
	FileName string
	Key      string
	FileSize int64
}

// AttachmentUploadResponse contains scaffold attachment upload response fields.
type AttachmentUploadResponse struct {
	AttachmentID   string
	FileUploadType int
	URL            string
	Cipher         EncryptedCipher
}

// EncryptedCipherField contains encrypted custom field values and plaintext metadata.
type EncryptedCipherField struct {
	Name     string
	Value    string
	Type     int
	LinkedID int
}
