package crypto

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAttachmentKey64() ports.AttachmentKey {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(255 - i)
	}
	return ports.AttachmentKey{Bytes: key}
}

func deterministicType2Bytes(t *testing.T, key []byte, plaintext []byte) string {
	t.Helper()
	require.Len(t, key, 64)
	iv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	ct, err := aes256cbcEncrypt(key[:32], iv, plaintext)
	require.NoError(t, err)
	mac := computeMac(key[32:], iv, ct)
	serialized, err := EncString{Type: 2, IV: iv, Data: ct, MAC: mac}.String()
	require.NoError(t, err)
	return serialized
}

func TestAttachmentKeyDecryptsDeterministicWrappedKey(t *testing.T) {
	eng := NewEngine()
	userKey := testUserKey64()
	attachmentKey := testAttachmentKey64()
	wrapped := deterministicType2Bytes(t, userKey.Bytes, attachmentKey.Bytes)

	got, err := eng.DecryptAttachmentKey(context.Background(), userKey, ports.EncryptedAttachment{
		ID:  "attachment-1",
		Key: wrapped,
	})
	require.NoError(t, err)
	assert.Equal(t, attachmentKey.Bytes, got.Bytes)
}

func TestAttachmentEncryptDecryptRoundtrip(t *testing.T) {
	eng := NewEngine()
	key := testAttachmentKey64()
	plaintext := bytes.Repeat([]byte("chunked attachment plaintext "), 64)

	var encrypted bytes.Buffer
	require.NoError(t, eng.EncryptAttachment(context.Background(), key, bytes.NewReader(plaintext), &encrypted))
	assert.NotContains(t, encrypted.String(), string(plaintext[:16]))

	var decrypted bytes.Buffer
	require.NoError(t, eng.DecryptAttachment(context.Background(), key, bytes.NewReader(encrypted.Bytes()), &decrypted))
	assert.Equal(t, plaintext, decrypted.Bytes())
}

func TestAttachmentEncryptDecryptEmptyContent(t *testing.T) {
	eng := NewEngine()
	key := testAttachmentKey64()

	var encrypted bytes.Buffer
	require.NoError(t, eng.EncryptAttachment(context.Background(), key, bytes.NewReader(nil), &encrypted))

	var decrypted bytes.Buffer
	require.NoError(t, eng.DecryptAttachment(context.Background(), key, bytes.NewReader(encrypted.Bytes()), &decrypted))
	assert.Empty(t, decrypted.Bytes())
}

func TestAttachmentDecryptMACMismatchWritesNoPlaintext(t *testing.T) {
	eng := NewEngine()
	key := testAttachmentKey64()

	var encrypted bytes.Buffer
	require.NoError(t, eng.EncryptAttachment(context.Background(), key, bytes.NewReader([]byte("secret attachment body")), &encrypted))
	buf := encrypted.Bytes()
	buf[20] ^= 0xff

	var decrypted bytes.Buffer
	err := eng.DecryptAttachment(context.Background(), key, bytes.NewReader(buf), &decrypted)
	require.Error(t, err)
	assert.True(t, coreerrors.Is(err, coreerrors.KindCrypto))
	assert.Empty(t, decrypted.Bytes())
}

func TestAttachmentInvalidKeyLength(t *testing.T) {
	eng := NewEngine()
	badKey := ports.AttachmentKey{Bytes: []byte("short")}

	err := eng.EncryptAttachment(context.Background(), badKey, bytes.NewReader([]byte("x")), io.Discard)
	require.Error(t, err)
	assert.True(t, coreerrors.Is(err, coreerrors.KindValidation))

	err = eng.DecryptAttachment(context.Background(), badKey, bytes.NewReader([]byte("x")), io.Discard)
	require.Error(t, err)
	assert.True(t, coreerrors.Is(err, coreerrors.KindValidation))
}

func TestAttachmentReaderErrorPropagates(t *testing.T) {
	eng := NewEngine()
	wantErr := errors.New("reader failed")
	err := eng.EncryptAttachment(context.Background(), testAttachmentKey64(), errReader{err: wantErr}, io.Discard)
	require.ErrorIs(t, err, wantErr)
}

func TestAttachmentWriterErrorPropagates(t *testing.T) {
	eng := NewEngine()
	wantErr := errors.New("writer failed")
	err := eng.EncryptAttachment(context.Background(), testAttachmentKey64(), bytes.NewReader([]byte("content")), errWriter{err: wantErr})
	require.ErrorIs(t, err, wantErr)
}

func TestAttachmentContextCancellation(t *testing.T) {
	eng := NewEngine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := eng.EncryptAttachment(ctx, testAttachmentKey64(), bytes.NewReader([]byte("content")), io.Discard)
	require.ErrorIs(t, err, context.Canceled)

	err = eng.DecryptAttachment(ctx, testAttachmentKey64(), bytes.NewReader([]byte("content")), io.Discard)
	require.ErrorIs(t, err, context.Canceled)
}

func TestAttachmentEncryptReadsPlaintextIncrementally(t *testing.T) {
	eng := NewEngine()
	key := testAttachmentKey64()
	plaintext := bytes.Repeat([]byte("streaming plaintext "), 64*1024)
	reader := &countingReader{r: bytes.NewReader(plaintext), maxChunk: 4096}

	var encrypted bytes.Buffer
	require.NoError(t, eng.EncryptAttachment(context.Background(), key, reader, &encrypted))
	assert.Greater(t, reader.reads, 10, "EncryptAttachment must read plaintext incrementally")
}

func TestAttachmentEncryptPropagatesSourceCloseError(t *testing.T) {
	eng := NewEngine()
	wantErr := errors.New("source close failed")
	src := &closeErrReader{Reader: bytes.NewReader([]byte("content")), err: wantErr}

	err := eng.EncryptAttachment(context.Background(), testAttachmentKey64(), src, io.Discard)
	require.ErrorIs(t, err, wantErr)
}

func TestAttachmentEncryptPropagatesDestinationCloseError(t *testing.T) {
	eng := NewEngine()
	wantErr := errors.New("destination close failed")
	dst := &closeErrWriter{Writer: &bytes.Buffer{}, err: wantErr}

	err := eng.EncryptAttachment(context.Background(), testAttachmentKey64(), bytes.NewReader([]byte("content")), dst)
	require.ErrorIs(t, err, wantErr)
}

func TestAttachmentDecryptPropagatesSourceCloseError(t *testing.T) {
	eng := NewEngine()
	key := testAttachmentKey64()
	var encrypted bytes.Buffer
	require.NoError(t, eng.EncryptAttachment(context.Background(), key, bytes.NewReader([]byte("content")), &encrypted))

	wantErr := errors.New("encrypted source close failed")
	src := &closeErrReader{Reader: bytes.NewReader(encrypted.Bytes()), err: wantErr}
	err := eng.DecryptAttachment(context.Background(), key, src, io.Discard)
	require.ErrorIs(t, err, wantErr)
}

func TestAttachmentDecryptPropagatesDestinationCloseError(t *testing.T) {
	eng := NewEngine()
	key := testAttachmentKey64()
	var encrypted bytes.Buffer
	require.NoError(t, eng.EncryptAttachment(context.Background(), key, bytes.NewReader([]byte("content")), &encrypted))

	wantErr := errors.New("plaintext destination close failed")
	dst := &closeErrWriter{Writer: &bytes.Buffer{}, err: wantErr}
	err := eng.DecryptAttachment(context.Background(), key, bytes.NewReader(encrypted.Bytes()), dst)
	require.ErrorIs(t, err, wantErr)
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

type countingReader struct {
	r        io.Reader
	maxChunk int
	reads    int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.reads++
	if len(p) > r.maxChunk {
		p = p[:r.maxChunk]
	}
	return r.r.Read(p)
}

type closeErrReader struct {
	io.Reader
	err error
}

func (r *closeErrReader) Close() error { return r.err }

type closeErrWriter struct {
	io.Writer
	err error
}

func (w *closeErrWriter) Close() error { return w.err }
