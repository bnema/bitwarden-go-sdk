package attachments

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/bnema/bitwarden-go-sdk/internal/adapters/crypto"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// benchKey returns a deterministic 64-byte attachment key.
func benchKey() ports.AttachmentKey {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(255 - i)
	}
	return ports.AttachmentKey{Bytes: key}
}

// benchUserKey returns a deterministic 64-byte user key.
func benchUserKey() ports.UserKey {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	return ports.UserKey{Bytes: key}
}

// benchUploadAPI is a minimal API client for upload benchmarks that consumes
// encrypted content without real network I/O.
type benchUploadAPI struct{}

func (benchUploadAPI) InitAttachmentUpload(_ context.Context, _ ports.AttachmentUploadRequest) (ports.AttachmentUploadResponse, error) {
	return ports.AttachmentUploadResponse{AttachmentID: "bench-att", FileUploadType: 0}, nil
}

func (benchUploadAPI) UploadAttachmentDirect(_ context.Context, _, _ string, content io.Reader) error {
	_, err := io.Copy(io.Discard, content)
	return err
}

func (benchUploadAPI) UploadAttachmentExternal(_ context.Context, _ string, content io.Reader) error {
	_, err := io.Copy(io.Discard, content)
	return err
}

func (benchUploadAPI) DeleteAttachment(_ context.Context, _, _ string) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}

// The remaining APIClient methods are not used by the upload or download paths.
func (benchUploadAPI) Config(_ context.Context) (ports.ServerConfig, error) {
	return ports.ServerConfig{}, nil
}
func (benchUploadAPI) AccountProfile(_ context.Context) (ports.AccountProfile, error) {
	return ports.AccountProfile{}, nil
}
func (benchUploadAPI) Subscription(_ context.Context) (ports.Subscription, error) {
	return ports.Subscription{}, nil
}
func (benchUploadAPI) Sync(_ context.Context, _ ports.SyncOptions) (ports.SyncResult, error) {
	return ports.SyncResult{}, nil
}
func (benchUploadAPI) CreateCipher(_ context.Context, _ ports.EncryptedCipher) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}
func (benchUploadAPI) UpdateCipher(_ context.Context, _ string, _ ports.EncryptedCipher) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}
func (benchUploadAPI) DeleteCipher(_ context.Context, _ string) error { return nil }
func (benchUploadAPI) TrashCipher(_ context.Context, _ string) error  { return nil }
func (benchUploadAPI) RestoreCipher(_ context.Context, _ string) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}
func (benchUploadAPI) GetAttachment(_ context.Context, _, _ string) (ports.EncryptedAttachmentMetadata, error) {
	return ports.EncryptedAttachmentMetadata{}, nil
}
func (benchUploadAPI) RenewAttachmentUploadURL(_ context.Context, _, _ string) (ports.AttachmentUploadResponse, error) {
	return ports.AttachmentUploadResponse{}, nil
}
func (benchUploadAPI) DownloadAttachment(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}
func (benchUploadAPI) ListFolders(_ context.Context) ([]ports.EncryptedFolder, error) {
	return nil, nil
}
func (benchUploadAPI) CreateFolder(_ context.Context, _ ports.EncryptedFolder) (ports.EncryptedFolder, error) {
	return ports.EncryptedFolder{}, nil
}
func (benchUploadAPI) UpdateFolder(_ context.Context, _ string, _ ports.EncryptedFolder) (ports.EncryptedFolder, error) {
	return ports.EncryptedFolder{}, nil
}
func (benchUploadAPI) DeleteFolder(_ context.Context, _ string) error { return nil }

// benchDownloadAPI returns pre-encrypted attachment data for download benchmarks.
type benchDownloadAPI struct {
	encrypted []byte
	key       string
}

func (a benchDownloadAPI) GetAttachment(_ context.Context, _, _ string) (ports.EncryptedAttachmentMetadata, error) {
	return ports.EncryptedAttachmentMetadata{
		ID:  "bench-att",
		Key: a.key,
		URL: "https://bench.example.com/dl",
	}, nil
}

func (a benchDownloadAPI) DownloadAttachment(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(a.encrypted)), nil
}

func (benchDownloadAPI) InitAttachmentUpload(_ context.Context, _ ports.AttachmentUploadRequest) (ports.AttachmentUploadResponse, error) {
	return ports.AttachmentUploadResponse{}, nil
}
func (benchDownloadAPI) UploadAttachmentDirect(_ context.Context, _, _ string, _ io.Reader) error {
	return nil
}
func (benchDownloadAPI) UploadAttachmentExternal(_ context.Context, _ string, _ io.Reader) error {
	return nil
}
func (benchDownloadAPI) DeleteAttachment(_ context.Context, _, _ string) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}
func (benchDownloadAPI) Config(_ context.Context) (ports.ServerConfig, error) {
	return ports.ServerConfig{}, nil
}
func (benchDownloadAPI) AccountProfile(_ context.Context) (ports.AccountProfile, error) {
	return ports.AccountProfile{}, nil
}
func (benchDownloadAPI) Subscription(_ context.Context) (ports.Subscription, error) {
	return ports.Subscription{}, nil
}
func (benchDownloadAPI) Sync(_ context.Context, _ ports.SyncOptions) (ports.SyncResult, error) {
	return ports.SyncResult{}, nil
}
func (benchDownloadAPI) CreateCipher(_ context.Context, _ ports.EncryptedCipher) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}
func (benchDownloadAPI) UpdateCipher(_ context.Context, _ string, _ ports.EncryptedCipher) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}
func (benchDownloadAPI) DeleteCipher(_ context.Context, _ string) error { return nil }
func (benchDownloadAPI) TrashCipher(_ context.Context, _ string) error  { return nil }
func (benchDownloadAPI) RestoreCipher(_ context.Context, _ string) (ports.EncryptedCipher, error) {
	return ports.EncryptedCipher{}, nil
}
func (benchDownloadAPI) RenewAttachmentUploadURL(_ context.Context, _, _ string) (ports.AttachmentUploadResponse, error) {
	return ports.AttachmentUploadResponse{}, nil
}
func (benchDownloadAPI) ListFolders(_ context.Context) ([]ports.EncryptedFolder, error) {
	return nil, nil
}
func (benchDownloadAPI) CreateFolder(_ context.Context, _ ports.EncryptedFolder) (ports.EncryptedFolder, error) {
	return ports.EncryptedFolder{}, nil
}
func (benchDownloadAPI) UpdateFolder(_ context.Context, _ string, _ ports.EncryptedFolder) (ports.EncryptedFolder, error) {
	return ports.EncryptedFolder{}, nil
}
func (benchDownloadAPI) DeleteFolder(_ context.Context, _ string) error { return nil }

// BenchmarkAttachmentUploadCore4MiB benchmarks uploading a 4 MiB attachment
// through the service layer with real encryption and a fake API that discards
// the stream. No real network I/O or logging.
func BenchmarkAttachmentUploadCore4MiB(b *testing.B) {
	eng := crypto.NewEngine()
	userKey := benchUserKey()
	attKey := benchKey()

	wrappedKey, err := eng.WrapAttachmentKey(context.Background(), userKey, attKey)
	if err != nil {
		b.Fatal(err)
	}

	svc := NewService(Dependencies{
		API:     benchUploadAPI{},
		Crypto:  eng,
		UserKey: userKey,
		Locked:  false,
	})

	plaintext := bytes.Repeat([]byte("A"), 4*1024*1024) // 4 MiB
	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()

	for range b.N {
		_, err := svc.Upload(context.Background(), UploadInput{
			CipherID:      "bench-cipher",
			FileName:      "bench-file.bin",
			Size:          int64(len(plaintext)),
			Plaintext:     bytes.NewReader(plaintext),
			AttachmentKey: attKey,
			WrappedKey:    wrappedKey,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAttachmentDownloadCore4MiB benchmarks downloading and decrypting
// a 4 MiB attachment through the service layer. The fake API returns
// pre-encrypted data; the real crypto engine performs decryption.
func BenchmarkAttachmentDownloadCore4MiB(b *testing.B) {
	eng := crypto.NewEngine()
	userKey := benchUserKey()
	attKey := benchKey()

	// Pre-encrypt 4 MiB of plaintext.
	plaintext := bytes.Repeat([]byte("B"), 4*1024*1024)
	var encryptedBuf bytes.Buffer
	if err := eng.EncryptAttachment(context.Background(), attKey, bytes.NewReader(plaintext), &encryptedBuf); err != nil {
		b.Fatal(err)
	}

	// Pre-wrap the attachment key.
	wrapped, err := eng.WrapAttachmentKey(context.Background(), userKey, attKey)
	if err != nil {
		b.Fatal(err)
	}

	svc := NewService(Dependencies{
		API:     benchDownloadAPI{encrypted: encryptedBuf.Bytes(), key: wrapped},
		Crypto:  eng,
		UserKey: userKey,
		Locked:  false,
	})

	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()

	for range b.N {
		err := svc.DownloadByID(context.Background(), "bench-cipher", "bench-att", io.Discard)
		if err != nil {
			b.Fatal(err)
		}
	}
}
