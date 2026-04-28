package bitwarden

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fakeCrypto embeds *mocks.MockCryptoEngine and overrides EncryptAttachment
// with a concurrency-safe implementation. This avoids testify mock races when
// EncryptAttachment is called from a goroutine via io.Pipe during upload tests.
type fakeCrypto struct {
	*mocks.MockCryptoEngine
	encryptAttachmentFunc  func(context.Context, ports.AttachmentKey, io.Reader, io.Writer) error
	encryptAttachmentCount atomic.Int32
}

func (f *fakeCrypto) EncryptAttachment(ctx context.Context, key ports.AttachmentKey, src io.Reader, dst io.Writer) error {
	f.encryptAttachmentCount.Add(1)
	if f.encryptAttachmentFunc != nil {
		return f.encryptAttachmentFunc(ctx, key, src, dst)
	}
	_, err := io.Copy(dst, src)
	return err
}

// fakeAPI embeds *mocks.MockAPIClient and overrides UploadAttachmentDirect
// and UploadAttachmentExternal to avoid passing *io.PipeReader through
// testify's argument formatting (which reads pipe internals via reflection
// while the encrypt goroutine writes to the pipe).
type fakeAPI struct {
	*mocks.MockAPIClient
	uploadDirectFn   func(ctx context.Context, cipherID, attachmentID string, body io.Reader) error
	uploadExternalFn func(ctx context.Context, url string, body io.Reader) error
}

func (f *fakeAPI) UploadAttachmentDirect(ctx context.Context, cipherID, attachmentID string, body io.Reader) error {
	args := f.MethodCalled("UploadAttachmentDirect", ctx, cipherID, attachmentID, "*io.PipeReader")
	if f.uploadDirectFn != nil {
		return f.uploadDirectFn(ctx, cipherID, attachmentID, body)
	}
	return args.Error(0)
}

func (f *fakeAPI) UploadAttachmentExternal(ctx context.Context, url string, body io.Reader) error {
	args := f.MethodCalled("UploadAttachmentExternal", ctx, url, "*io.PipeReader")
	if f.uploadExternalFn != nil {
		return f.uploadExternalFn(ctx, url, body)
	}
	return args.Error(0)
}

func TestAttachmentsMetadataSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		withIdentityClient(identity),
		withCryptoEngine(crypto),
		withTokenStore(store),
		withAPIClient(api),
	)
	require.NoError(t, err)
	loginAndUnlock(t, client, identity, crypto, store)

	api.EXPECT().
		GetAttachment(mock.Anything, "c1", "a1").
		Return(ports.EncryptedAttachmentMetadata{
			ID:       "a1",
			CipherID: "c1",
			FileName: "enc-foo.txt",
			Key:      "enc-key",
			Size:     1024,
			SizeName: "1 KB",
			URL:      "https://example.com/dl",
		}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(mock.Anything, mock.Anything, "enc-foo.txt").
		Return("foo.txt", nil).
		Once()

	att, err := client.Attachments().Metadata(context.Background(), "c1", "a1")
	require.NoError(t, err)
	assert.Equal(t, "a1", att.ID)
	assert.Equal(t, "c1", att.CipherID)
	assert.Equal(t, "foo.txt", att.FileName)
	assert.Equal(t, int64(1024), att.Size)
	assert.Equal(t, "1 KB", att.SizeName)
	assert.Equal(t, "https://example.com/dl", att.URL)
}

func TestAttachmentsUploadSuccess(t *testing.T) {
	api := &fakeAPI{MockAPIClient: mocks.NewMockAPIClient(t)}
	crypto := &fakeCrypto{MockCryptoEngine: mocks.NewMockCryptoEngine(t)}
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		withIdentityClient(identity),
		withCryptoEngine(crypto),
		withTokenStore(store),
		withAPIClient(api),
	)
	require.NoError(t, err)
	loginAndUnlock(t, client, identity, crypto.MockCryptoEngine, store)

	// WrapAttachmentKey must be called with the user key and some attachment key
	crypto.EXPECT().
		WrapAttachmentKey(mock.Anything, mock.Anything, mock.AnythingOfType("ports.AttachmentKey")).
		Return("wrapped-key", nil).
		Once()

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, mock.Anything, "foo.txt").
		Return("enc-foo.txt", nil).
		Once()

	api.EXPECT().
		InitAttachmentUpload(mock.Anything, ports.AttachmentUploadRequest{
			CipherID: "c1",
			FileName: "enc-foo.txt",
			Key:      "wrapped-key",
			FileSize: 4,
		}).
		Return(ports.AttachmentUploadResponse{
			AttachmentID:   "a-new",
			FileUploadType: 0,
			Cipher:         ports.EncryptedCipher{ID: "c1"},
		}, nil).
		Once()

	api.EXPECT().
		UploadAttachmentDirect(mock.Anything, "c1", "a-new", "*io.PipeReader").
		Return(nil).
		Once()

	att, err := client.Attachments().Upload(context.Background(), AttachmentUploadOptions{
		ItemID:   "c1",
		FileName: "foo.txt",
		Size:     4,
		Reader:   bytes.NewReader([]byte("data")),
	})
	require.NoError(t, err)
	assert.Equal(t, "a-new", att.ID)
	assert.Equal(t, "c1", att.CipherID)
	assert.Equal(t, "foo.txt", att.FileName)
}

func TestAttachmentsDownloadSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		withIdentityClient(identity),
		withCryptoEngine(crypto),
		withTokenStore(store),
		withAPIClient(api),
	)
	require.NoError(t, err)
	loginAndUnlock(t, client, identity, crypto, store)

	api.EXPECT().
		GetAttachment(mock.Anything, "c1", "a1").
		Return(ports.EncryptedAttachmentMetadata{
			ID:  "a1",
			Key: "enc-key",
			URL: "https://example.com/dl",
		}, nil).
		Once()

	api.EXPECT().
		DownloadAttachment(mock.Anything, "https://example.com/dl").
		Return(io.NopCloser(bytes.NewReader([]byte("encrypted-data"))), nil).
		Once()

	crypto.EXPECT().
		DecryptAttachmentKey(mock.Anything, mock.Anything, ports.EncryptedAttachment{ID: "a1", Key: "enc-key"}).
		Return(ports.AttachmentKey{Bytes: make([]byte, 64)}, nil).
		Once()

	crypto.EXPECT().
		DecryptAttachment(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil).
		Once()

	var dst bytes.Buffer
	err = client.Attachments().Download(context.Background(), "c1", "a1", &dst)
	require.NoError(t, err)
}

func TestAttachmentsDeleteSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		withIdentityClient(identity),
		withCryptoEngine(crypto),
		withTokenStore(store),
		withAPIClient(api),
	)
	require.NoError(t, err)
	loginAndUnlock(t, client, identity, crypto, store)

	api.EXPECT().
		DeleteAttachment(mock.Anything, "c1", "a1").
		Return(ports.EncryptedCipher{ID: "c1"}, nil).
		Once()

	err = client.Attachments().Delete(context.Background(), "c1", "a1")
	require.NoError(t, err)
}

func TestAttachmentsLockedReturnsErrLocked(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		withIdentityClient(identity),
		withCryptoEngine(crypto),
		withTokenStore(store),
		withAPIClient(api),
	)
	require.NoError(t, err)
	require.True(t, client.IsLocked())

	_, err = client.Attachments().Metadata(context.Background(), "c1", "a1")
	require.ErrorIs(t, err, ErrLocked)

	_, err = client.Attachments().Upload(context.Background(), AttachmentUploadOptions{
		ItemID: "c1", FileName: "f.txt", Size: 1, Reader: bytes.NewReader(nil),
	})
	require.ErrorIs(t, err, ErrLocked)

	err = client.Attachments().Download(context.Background(), "c1", "a1", io.Discard)
	require.ErrorIs(t, err, ErrLocked)

	err = client.Attachments().Delete(context.Background(), "c1", "a1")
	require.ErrorIs(t, err, ErrLocked)
}

func TestAttachmentsUploadWithStringsReaderUsesWrapAttachmentKey(t *testing.T) {
	api := &fakeAPI{MockAPIClient: mocks.NewMockAPIClient(t)}
	crypto := &fakeCrypto{MockCryptoEngine: mocks.NewMockCryptoEngine(t)}
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		withIdentityClient(identity),
		withCryptoEngine(crypto),
		withTokenStore(store),
		withAPIClient(api),
	)
	require.NoError(t, err)
	loginAndUnlock(t, client, identity, crypto.MockCryptoEngine, store)

	crypto.EXPECT().
		WrapAttachmentKey(mock.Anything, mock.Anything, mock.AnythingOfType("ports.AttachmentKey")).
		Return("wrapped-key", nil).
		Once()

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, mock.Anything, "hello.txt").
		Return("enc-hello.txt", nil).
		Once()

	api.EXPECT().
		InitAttachmentUpload(mock.Anything, ports.AttachmentUploadRequest{
			CipherID: "c1", FileName: "enc-hello.txt", Key: "wrapped-key", FileSize: 11,
		}).
		Return(ports.AttachmentUploadResponse{
			AttachmentID: "a-new", FileUploadType: 0,
		}, nil).
		Once()

	api.EXPECT().
		UploadAttachmentDirect(mock.Anything, "c1", "a-new", "*io.PipeReader").
		Return(nil).
		Once()

	_, err = client.Attachments().Upload(context.Background(), AttachmentUploadOptions{
		ItemID: "c1", FileName: "hello.txt", Size: 11,
		Reader: bytes.NewReader([]byte("hello world")),
	})
	require.NoError(t, err)
}
