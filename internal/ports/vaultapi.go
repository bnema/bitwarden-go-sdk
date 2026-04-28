package ports

import "context"

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
}

// ServerConfig contains scaffold server configuration fields.
type ServerConfig struct {
	Version      string
	FeatureFlags map[string]bool
	ServerName   string
}

// AccountProfile contains scaffold account profile fields.
type AccountProfile struct {
	ID    string
	Email string
	Name  string
}

// Subscription contains scaffold subscription fields.
type Subscription struct {
	Plan      string
	IsPremium bool
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

// EncryptedCipher contains scaffold encrypted cipher fields.
type EncryptedCipher struct {
	ID   string
	Type int
	Name string
}
