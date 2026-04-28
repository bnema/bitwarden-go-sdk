package out

import "context"

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

type ServerConfig struct {
	Version      string
	FeatureFlags map[string]bool
	ServerName   string
}

type AccountProfile struct {
	ID    string
	Email string
	Name  string
}

type Subscription struct {
	Plan      string
	IsPremium bool
}

type SyncOptions struct {
	ExcludeDomains bool
}

type SyncResult struct {
	Profile AccountProfile
	Folders []EncryptedFolder
	Ciphers []EncryptedCipher
}

type EncryptedFolder struct {
	ID   string
	Name string
}

type EncryptedCipher struct {
	ID   string
	Type int
	Name string
}
