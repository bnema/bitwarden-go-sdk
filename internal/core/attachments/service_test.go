package attachments

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
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

var testUserKey = ports.UserKey{Bytes: []byte("test-user-key-32-bytes-for-testing!")}
var testAttachmentKey = ports.AttachmentKey{Bytes: []byte("test-attachment-key-32-bytes-long!!")}

// ---------- Metadata ----------

func TestAttachmentMetadataSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

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
		DecryptFolderName(mock.Anything, testUserKey, "enc-foo.txt").
		Return("foo.txt", nil).
		Once()

	att, err := svc.Metadata(context.Background(), "c1", "a1")
	require.NoError(t, err)
	assert.Equal(t, "a1", att.ID)
	assert.Equal(t, "c1", att.CipherID)
	assert.Equal(t, "foo.txt", att.FileName)
	assert.Equal(t, int64(1024), att.Size)
	assert.Equal(t, "1 KB", att.SizeName)
	assert.Equal(t, "https://example.com/dl", att.URL)
}

func TestAttachmentMetadataLocked(t *testing.T) {
	svc := NewService(Dependencies{Locked: true})

	_, err := svc.Metadata(context.Background(), "c1", "a1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked))
}

func TestAttachmentMetadataAPIFailure(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	api.EXPECT().
		GetAttachment(mock.Anything, "c1", "a1").
		Return(ports.EncryptedAttachmentMetadata{}, assert.AnError).
		Once()

	_, err := svc.Metadata(context.Background(), "c1", "a1")
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestAttachmentMetadataDecryptFailure(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	api.EXPECT().
		GetAttachment(mock.Anything, "c1", "a1").
		Return(ports.EncryptedAttachmentMetadata{
			ID:       "a1",
			CipherID: "c1",
			FileName: "enc-bad",
		}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(mock.Anything, testUserKey, "enc-bad").
		Return("", assert.AnError).
		Once()

	_, err := svc.Metadata(context.Background(), "c1", "a1")
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

// ---------- Upload ----------

func TestAttachmentUploadDirectSuccess(t *testing.T) {
	api := &fakeAPI{MockAPIClient: mocks.NewMockAPIClient(t)}
	crypto := &fakeCrypto{MockCryptoEngine: mocks.NewMockCryptoEngine(t)}

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	plaintext := bytes.NewReader([]byte("hello attachment data"))

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, testUserKey, "foo.txt").
		Return("enc-foo.txt", nil).
		Once()

	api.EXPECT().
		InitAttachmentUpload(mock.Anything, ports.AttachmentUploadRequest{
			CipherID: "c1",
			FileName: "enc-foo.txt",
			Key:      "wrapped-key",
			FileSize: 20,
		}).
		Return(ports.AttachmentUploadResponse{
			AttachmentID:   "a-new",
			FileUploadType: 0,
			URL:            "",
			Cipher:         ports.EncryptedCipher{ID: "c1"},
		}, nil).
		Once()

	api.EXPECT().
		UploadAttachmentDirect(mock.Anything, "c1", "a-new", "*io.PipeReader").
		Return(nil).
		Once()

	att, err := svc.Upload(context.Background(), UploadInput{
		CipherID:      "c1",
		FileName:      "foo.txt",
		Size:          20,
		Plaintext:     plaintext,
		AttachmentKey: testAttachmentKey,
		WrappedKey:    "wrapped-key",
	})
	require.NoError(t, err)
	assert.Equal(t, "a-new", att.ID)
	assert.Equal(t, "c1", att.CipherID)
	assert.Equal(t, "foo.txt", att.FileName)
	assert.Equal(t, int64(20), att.Size)
}

func TestAttachmentUploadExternalSuccess(t *testing.T) {
	api := &fakeAPI{MockAPIClient: mocks.NewMockAPIClient(t)}
	crypto := &fakeCrypto{MockCryptoEngine: mocks.NewMockCryptoEngine(t)}

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	plaintext := bytes.NewReader([]byte("hello attachment data"))

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, testUserKey, "foo.txt").
		Return("enc-foo.txt", nil).
		Once()

	api.EXPECT().
		InitAttachmentUpload(mock.Anything, ports.AttachmentUploadRequest{
			CipherID: "c1",
			FileName: "enc-foo.txt",
			Key:      "wrapped-key",
			FileSize: 20,
		}).
		Return(ports.AttachmentUploadResponse{
			AttachmentID:   "a-new",
			FileUploadType: 1,
			URL:            "https://upload.example.com/put",
			Cipher:         ports.EncryptedCipher{ID: "c1"},
		}, nil).
		Once()

	api.EXPECT().
		UploadAttachmentExternal(mock.Anything, "https://upload.example.com/put", "*io.PipeReader").
		Return(nil).
		Once()

	att, err := svc.Upload(context.Background(), UploadInput{
		CipherID:      "c1",
		FileName:      "foo.txt",
		Size:          20,
		Plaintext:     plaintext,
		AttachmentKey: testAttachmentKey,
		WrappedKey:    "wrapped-key",
	})
	require.NoError(t, err)
	assert.Equal(t, "a-new", att.ID)
	assert.Equal(t, "c1", att.CipherID)
	assert.Equal(t, "foo.txt", att.FileName)
	assert.Equal(t, int64(20), att.Size)
}

func TestAttachmentUploadLocked(t *testing.T) {
	svc := NewService(Dependencies{Locked: true})

	_, err := svc.Upload(context.Background(), UploadInput{
		CipherID: "c1",
		FileName: "foo.txt",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked))
}

func TestAttachmentUploadInitFailure(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, testUserKey, "foo.txt").
		Return("enc-foo.txt", nil).
		Once()

	api.EXPECT().
		InitAttachmentUpload(mock.Anything, ports.AttachmentUploadRequest{
			CipherID: "c1",
			FileName: "enc-foo.txt",
			Key:      "wrapped-key",
			FileSize: 20,
		}).
		Return(ports.AttachmentUploadResponse{}, assert.AnError).
		Once()

	_, err := svc.Upload(context.Background(), UploadInput{
		CipherID:      "c1",
		FileName:      "foo.txt",
		Size:          20,
		Plaintext:     bytes.NewReader(nil),
		AttachmentKey: testAttachmentKey,
		WrappedKey:    "wrapped-key",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestAttachmentUploadEncryptFailure(t *testing.T) {
	api := &fakeAPI{MockAPIClient: mocks.NewMockAPIClient(t)}
	crypto := &fakeCrypto{
		MockCryptoEngine: mocks.NewMockCryptoEngine(t),
		encryptAttachmentFunc: func(_ context.Context, _ ports.AttachmentKey, _ io.Reader, _ io.Writer) error {
			return assert.AnError
		},
	}

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	plaintext := bytes.NewReader([]byte("data"))

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, testUserKey, "foo.txt").
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
		}, nil).
		Once()

	api.EXPECT().
		UploadAttachmentDirect(mock.Anything, "c1", "a-new", "*io.PipeReader").
		Return(nil).
		Maybe()

	// Rollback: DeleteAttachment is called due to encrypt failure
	api.EXPECT().
		DeleteAttachment(mock.Anything, "c1", "a-new").
		Return(ports.EncryptedCipher{}, nil).
		Once()

	_, err := svc.Upload(context.Background(), UploadInput{
		CipherID:      "c1",
		FileName:      "foo.txt",
		Size:          4,
		Plaintext:     plaintext,
		AttachmentKey: testAttachmentKey,
		WrappedKey:    "wrapped-key",
	})
	require.Error(t, err)
}

func TestAttachmentUploadGeneratedSuccess(t *testing.T) {
	api := &fakeAPI{MockAPIClient: mocks.NewMockAPIClient(t)}
	crypto := &fakeCrypto{MockCryptoEngine: mocks.NewMockCryptoEngine(t)}

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	plaintext := bytes.NewReader([]byte("data"))

	crypto.EXPECT().
		WrapAttachmentKey(mock.Anything, testUserKey, mock.AnythingOfType("ports.AttachmentKey")).
		Return("wrapped-key", nil).
		Once()

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, testUserKey, "foo.txt").
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
		}, nil).
		Once()

	api.EXPECT().
		UploadAttachmentDirect(mock.Anything, "c1", "a-new", "*io.PipeReader").
		Return(nil).
		Once()

	att, err := svc.UploadGenerated(context.Background(), "c1", "foo.txt", 4, plaintext)
	require.NoError(t, err)
	assert.Equal(t, "a-new", att.ID)
	assert.Equal(t, "c1", att.CipherID)
	assert.Equal(t, "foo.txt", att.FileName)
	assert.Equal(t, int64(4), att.Size)
}

func TestAttachmentUploadGeneratedLocked(t *testing.T) {
	svc := NewService(Dependencies{Locked: true})

	_, err := svc.UploadGenerated(context.Background(), "c1", "foo.txt", 4, bytes.NewReader(nil))
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked))
}

func TestAttachmentDownloadByIDSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

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

	api.EXPECT().
		DownloadAttachment(mock.Anything, "https://example.com/dl").
		Return(io.NopCloser(bytes.NewReader([]byte("encrypted-data"))), nil).
		Once()

	crypto.EXPECT().
		DecryptAttachmentKey(mock.Anything, testUserKey, ports.EncryptedAttachment{ID: "a1", Key: "enc-key"}).
		Return(testAttachmentKey, nil).
		Once()

	crypto.EXPECT().
		DecryptAttachment(mock.Anything, testAttachmentKey, mock.Anything, mock.Anything).
		Return(nil).
		Once()

	var dst bytes.Buffer
	err := svc.DownloadByID(context.Background(), "c1", "a1", &dst)
	require.NoError(t, err)
}

func TestAttachmentDownloadByIDLocked(t *testing.T) {
	svc := NewService(Dependencies{Locked: true})

	err := svc.DownloadByID(context.Background(), "c1", "a1", io.Discard)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked))
}

func TestAttachmentUploadRollbackOnUploadError(t *testing.T) {
	api := &fakeAPI{MockAPIClient: mocks.NewMockAPIClient(t)}
	crypto := &fakeCrypto{MockCryptoEngine: mocks.NewMockCryptoEngine(t)}

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	plaintext := bytes.NewReader([]byte("data"))

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, testUserKey, "foo.txt").
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
		}, nil).
		Once()

	uploadErr := assert.AnError

	api.EXPECT().
		UploadAttachmentDirect(mock.Anything, "c1", "a-new", "*io.PipeReader").
		Return(uploadErr).
		Once()

	// Rollback: DeleteAttachment must be called
	api.EXPECT().
		DeleteAttachment(mock.Anything, "c1", "a-new").
		Return(ports.EncryptedCipher{}, nil).
		Once()

	_, err := svc.Upload(context.Background(), UploadInput{
		CipherID:      "c1",
		FileName:      "foo.txt",
		Size:          4,
		Plaintext:     plaintext,
		AttachmentKey: testAttachmentKey,
		WrappedKey:    "wrapped-key",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestAttachmentUploadRollbackDeleteError(t *testing.T) {
	api := &fakeAPI{MockAPIClient: mocks.NewMockAPIClient(t)}
	crypto := &fakeCrypto{MockCryptoEngine: mocks.NewMockCryptoEngine(t)}

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	plaintext := bytes.NewReader([]byte("data"))

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, testUserKey, "foo.txt").
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
		}, nil).
		Once()

	uploadErr := assert.AnError

	api.EXPECT().
		UploadAttachmentDirect(mock.Anything, "c1", "a-new", "*io.PipeReader").
		Return(uploadErr).
		Once()

	// Rollback: DeleteAttachment fails too.
	rollbackErr := stderrors.New("delete failed")
	api.EXPECT().
		DeleteAttachment(mock.Anything, "c1", "a-new").
		Return(ports.EncryptedCipher{}, rollbackErr).
		Once()

	_, err := svc.Upload(context.Background(), UploadInput{
		CipherID:      "c1",
		FileName:      "foo.txt",
		Size:          4,
		Plaintext:     plaintext,
		AttachmentKey: testAttachmentKey,
		WrappedKey:    "wrapped-key",
	})
	require.Error(t, err)

	// The error must be a core error indicating rollback failure.
	var cerr *errors.Error
	require.ErrorAs(t, err, &cerr)
	assert.Equal(t, errors.KindTemporary, cerr.Kind)
	assert.Equal(t, "attachments.Service.Upload", cerr.Op)
	assert.Equal(t, "rollback_failed", cerr.Code)
	assert.Equal(t, "upload failed and rollback delete failed", cerr.Message)
	// The cause should be the rollback error (not the upload error).
	require.ErrorIs(t, cerr, rollbackErr)
	// Must not contain secrets / file names / tokens in message.
	assert.NotContains(t, cerr.Error(), "foo.txt")
	assert.NotContains(t, cerr.Error(), "data")
}

// ---------- Download ----------

func TestAttachmentDownloadSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	meta := ports.EncryptedAttachmentMetadata{
		ID:  "a1",
		Key: "enc-key",
	}

	encrypted := bytes.NewReader([]byte("encrypted-data"))
	var dst bytes.Buffer

	crypto.EXPECT().
		DecryptAttachmentKey(mock.Anything, testUserKey, ports.EncryptedAttachment{ID: "a1", Key: "enc-key"}).
		Return(testAttachmentKey, nil).
		Once()

	crypto.EXPECT().
		DecryptAttachment(mock.Anything, testAttachmentKey, encrypted, &dst).
		Return(nil).
		Once()

	err := svc.Download(context.Background(), meta, encrypted, &dst)
	require.NoError(t, err)
}

func TestAttachmentDownloadLocked(t *testing.T) {
	svc := NewService(Dependencies{Locked: true})

	err := svc.Download(context.Background(), ports.EncryptedAttachmentMetadata{}, nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked))
}

func TestAttachmentDownloadKeyDecryptFailure(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	meta := ports.EncryptedAttachmentMetadata{
		ID:  "a1",
		Key: "bad-key",
	}

	crypto.EXPECT().
		DecryptAttachmentKey(mock.Anything, testUserKey, ports.EncryptedAttachment{ID: "a1", Key: "bad-key"}).
		Return(ports.AttachmentKey{}, assert.AnError).
		Once()

	err := svc.Download(context.Background(), meta, bytes.NewReader(nil), io.Discard)
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestAttachmentDownloadDecryptStreamFailure(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	meta := ports.EncryptedAttachmentMetadata{
		ID:  "a1",
		Key: "enc-key",
	}

	encrypted := bytes.NewReader([]byte("bad-data"))
	var dst bytes.Buffer

	crypto.EXPECT().
		DecryptAttachmentKey(mock.Anything, testUserKey, ports.EncryptedAttachment{ID: "a1", Key: "enc-key"}).
		Return(testAttachmentKey, nil).
		Once()

	crypto.EXPECT().
		DecryptAttachment(mock.Anything, testAttachmentKey, encrypted, &dst).
		Return(assert.AnError).
		Once()

	err := svc.Download(context.Background(), meta, encrypted, &dst)
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

// ---------- Delete ----------

func TestAttachmentDeleteSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	api.EXPECT().
		DeleteAttachment(mock.Anything, "c1", "a1").
		Return(ports.EncryptedCipher{ID: "c1"}, nil).
		Once()

	err := svc.Delete(context.Background(), "c1", "a1")
	require.NoError(t, err)
}

func TestAttachmentDeleteLocked(t *testing.T) {
	svc := NewService(Dependencies{Locked: true})

	err := svc.Delete(context.Background(), "c1", "a1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked))
}

func TestAttachmentDeleteAPIFailure(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	api.EXPECT().
		DeleteAttachment(mock.Anything, "c1", "a1").
		Return(ports.EncryptedCipher{}, assert.AnError).
		Once()

	err := svc.Delete(context.Background(), "c1", "a1")
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}
