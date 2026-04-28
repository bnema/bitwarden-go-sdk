package vault

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// ---------------------------------------------------------------------------
// Fakes for deterministic benchmarks (no mock expectation counting).
// ---------------------------------------------------------------------------

type benchFakeAPI struct {
	result ports.SyncResult
}

func (f *benchFakeAPI) Sync(_ context.Context, _ ports.SyncOptions) (ports.SyncResult, error) {
	return f.result, nil
}

func (f *benchFakeAPI) Config(_ context.Context) (ports.ServerConfig, error) {
	return ports.ServerConfig{}, nil
}

func (f *benchFakeAPI) AccountProfile(_ context.Context) (ports.AccountProfile, error) {
	return ports.AccountProfile{}, nil
}

func (f *benchFakeAPI) Subscription(_ context.Context) (ports.Subscription, error) {
	return ports.Subscription{}, nil
}

func (f *benchFakeAPI) CreateCipher(_ context.Context, _ ports.EncryptedCipher) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}

func (f *benchFakeAPI) UpdateCipher(_ context.Context, _ string, _ ports.EncryptedCipher) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}

func (f *benchFakeAPI) DeleteCipher(_ context.Context, _ string) error {
	return nil
}

func (f *benchFakeAPI) TrashCipher(_ context.Context, _ string) error {
	return nil
}

func (f *benchFakeAPI) RestoreCipher(_ context.Context, _ string) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}

func (f *benchFakeAPI) ListFolders(_ context.Context) ([]ports.EncryptedFolder, error) {
	return nil, nil
}

func (f *benchFakeAPI) CreateFolder(_ context.Context, _ ports.EncryptedFolder) (ports.EncryptedFolder, error) {
	return ports.EncryptedFolder{}, nil
}

func (f *benchFakeAPI) UpdateFolder(_ context.Context, _ string, _ ports.EncryptedFolder) (ports.EncryptedFolder, error) {
	return ports.EncryptedFolder{}, nil
}

func (f *benchFakeAPI) DeleteFolder(_ context.Context, _ string) error {
	return nil
}

func (f *benchFakeAPI) GetAttachment(_ context.Context, _, _ string) (ports.EncryptedAttachmentMetadata, error) {
	return ports.EncryptedAttachmentMetadata{}, nil
}

func (f *benchFakeAPI) InitAttachmentUpload(_ context.Context, _ ports.AttachmentUploadRequest) (ports.AttachmentUploadResponse, error) {
	return ports.AttachmentUploadResponse{}, nil
}

func (f *benchFakeAPI) UploadAttachmentDirect(_ context.Context, _, _ string, _ io.Reader) error {
	return nil
}

func (f *benchFakeAPI) UploadAttachmentExternal(_ context.Context, _ string, _ io.Reader) error {
	return nil
}

func (f *benchFakeAPI) RenewAttachmentUploadURL(_ context.Context, _, _ string) (ports.AttachmentUploadResponse, error) {
	return ports.AttachmentUploadResponse{}, nil
}

func (f *benchFakeAPI) DeleteAttachment(_ context.Context, _, _ string) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}

func (f *benchFakeAPI) DownloadAttachment(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

type benchFakeCrypto struct{}

func (benchFakeCrypto) DeriveMasterKey(_ context.Context, _ ports.MasterKeyInput) (ports.MasterKey, error) {
	return ports.MasterKey{}, nil
}

func (benchFakeCrypto) MakeAuthHash(_ context.Context, _ ports.AuthHashInput) (ports.AuthHash, error) {
	return "", nil
}

func (benchFakeCrypto) UnlockUserKey(_ context.Context, _ ports.UserKeyInput) (ports.UserKey, error) {
	return ports.UserKey{}, nil
}

func (benchFakeCrypto) DecryptCipher(_ context.Context, _ ports.UserKey, ec ports.EncryptedCipher) (ports.Cipher, error) {
	return ports.Cipher{
		ID:       ec.ID,
		Type:     ec.Type,
		Name:     ec.Name,
		Notes:    ec.Notes,
		Favorite: ec.Favorite,
		FolderID: ec.FolderID,
	}, nil
}

func (benchFakeCrypto) EncryptCipher(_ context.Context, _ ports.UserKey, _ ports.Cipher) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}

func (benchFakeCrypto) WrapAttachmentKey(_ context.Context, _ ports.UserKey, _ ports.AttachmentKey) (string, error) {
	return "", nil
}

func (benchFakeCrypto) DecryptAttachmentKey(_ context.Context, _ ports.UserKey, _ ports.EncryptedAttachment) (ports.AttachmentKey, error) {
	return ports.AttachmentKey{}, nil
}

func (benchFakeCrypto) EncryptAttachment(_ context.Context, _ ports.AttachmentKey, _ io.Reader, _ io.Writer) error {
	return nil
}

func (benchFakeCrypto) DecryptAttachment(_ context.Context, _ ports.AttachmentKey, _ io.Reader, _ io.Writer) error {
	return nil
}

func (benchFakeCrypto) EncryptFolderName(_ context.Context, _ ports.UserKey, name string) (string, error) {
	return name, nil
}

func (benchFakeCrypto) DecryptFolderName(_ context.Context, _ ports.UserKey, encryptedName string) (string, error) {
	return encryptedName, nil
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// BenchmarkSyncDecrypt measures a full Sync call with N encrypted ciphers.
func BenchmarkSyncDecrypt(b *testing.B) {
	const n = 100

	encCiphers := make([]ports.EncryptedCipher, n)
	for i := 0; i < n; i++ {
		encCiphers[i] = ports.EncryptedCipher{
			ID:   "enc-id",
			Type: 1,
			Name: "enc-name",
		}
	}

	api := &benchFakeAPI{result: ports.SyncResult{
		Ciphers: encCiphers,
		Folders: []ports.EncryptedFolder{
			{ID: "f1", Name: "enc-folder"},
		},
	}}

	svc := NewService(Dependencies{
		API:    api,
		Crypto: benchFakeCrypto{},
		Locked: false,
	})

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := svc.Sync(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkList measures List on a service with N items.
func BenchmarkList(b *testing.B) {
	const n = 1000

	items := make([]Item, n)
	for i := 0; i < n; i++ {
		items[i] = Item{
			ID:   "id",
			Name: "item",
		}
	}

	svc := NewService(Dependencies{Locked: false})
	svc.snapshot = NewSnapshot(items, nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := svc.List()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSearch measures Search with a query matching half the items.
func BenchmarkSearch(b *testing.B) {
	const n = 1000

	items := make([]Item, n)
	for i := 0; i < n; i++ {
		items[i] = Item{
			ID:   "id",
			Name: "item",
		}
	}
	// Make half the items match "searchable".
	for i := 0; i < n/2; i++ {
		items[i] = Item{
			ID:   "id",
			Name: "searchable-item",
		}
	}

	svc := NewService(Dependencies{Locked: false})
	svc.snapshot = NewSnapshot(items, nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := svc.Search("searchable")
		if err != nil {
			b.Fatal(err)
		}
	}
}
