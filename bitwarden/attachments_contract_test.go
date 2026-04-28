package bitwarden

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	adapterhttp "github.com/bnema/bitwarden-go-sdk/internal/adapters/http"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/bnema/bitwarden-go-sdk/internal/testkit/bitwardenremote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestPublicAttachmentMetadataContract verifies the public Attachments().Metadata
// flow against the testkit server. It uses a mock crypto engine for filename
// decryption and a real HTTP VaultClient wired to the testkit.
func TestPublicAttachmentMetadataContract(t *testing.T) {
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())
	identity := server.NewIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	store := mocks.NewMockTokenStore(t)

	// Create a real VaultClient pointing at the testkit server.
	tokenProvider := func(_ context.Context) (ports.SecretBytes, error) {
		return ports.NewSecretBytes([]byte("test-access-token")), nil
	}
	api, err := adapterhttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	require.NoError(t, err)

	// Login expectations.
	masterKey := ports.MasterKey{Bytes: []byte("deterministic-master-key")}
	userKey := ports.UserKey{Bytes: []byte("deterministic-user-key")}
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("deterministic-auth-hash"), nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, mock.Anything).Return(userKey, nil)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)

	// Metadata decryption expectation.
	crypto.EXPECT().
		DecryptFolderName(mock.Anything, mock.Anything, "2.sanitized-iv|sanitized-file-name|sanitized-mac").
		Return("report.pdf", nil).
		Once()

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	_, err = client.BeginLogin(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	require.False(t, client.IsLocked())

	att, err := client.Attachments().Metadata(context.Background(), "cipher-id-1", "attachment-id-1")
	require.NoError(t, err)
	assert.Equal(t, "attachment-id-1", att.ID)
	assert.Equal(t, "cipher-id-1", att.CipherID)
	assert.Equal(t, "report.pdf", att.FileName)
	assert.Equal(t, int64(128), att.Size)
	assert.Equal(t, "128 B", att.SizeName)
	// URL should point to the self-contained download endpoint.
	assert.Contains(t, att.URL, "/attachment-download/attachment-id-1")

	// Assert recorder saw the GET request for metadata.
	require.NoError(t, server.Recorder().AssertRequest("GET", "/ciphers/cipher-id-1/attachment/attachment-id-1"))

	// Assert no raw bodies or secret values leaked.
	require.NoError(t, server.Recorder().AssertNoRawBodies())
}

// TestPublicAttachmentUploadContract verifies the public Attachments().Upload
// flow against the testkit server using direct (single-step) upload. It uses
// a mock crypto engine and a real HTTP VaultClient.
func TestPublicAttachmentUploadContract(t *testing.T) {
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario(bitwardenremote.WithDirectAttachmentUpload()))
	identity := server.NewIdentityClient(t)
	crypto := &fakeCrypto{MockCryptoEngine: mocks.NewMockCryptoEngine(t)}
	store := mocks.NewMockTokenStore(t)

	tokenProvider := func(_ context.Context) (ports.SecretBytes, error) {
		return ports.NewSecretBytes([]byte("test-access-token")), nil
	}
	api, err := adapterhttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	require.NoError(t, err)

	// Login expectations.
	masterKey := ports.MasterKey{Bytes: []byte("deterministic-master-key")}
	userKey := ports.UserKey{Bytes: []byte("deterministic-user-key")}
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("deterministic-auth-hash"), nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, mock.Anything).Return(userKey, nil)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)

	// Upload crypto expectations.
	crypto.EXPECT().
		WrapAttachmentKey(mock.Anything, mock.Anything, mock.AnythingOfType("ports.AttachmentKey")).
		Return("wrapped-key", nil).
		Once()
	crypto.EXPECT().
		EncryptFolderName(mock.Anything, mock.Anything, "hello.txt").
		Return("enc-hello.txt", nil).
		Once()

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	_, err = client.BeginLogin(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	require.False(t, client.IsLocked())

	att, err := client.Attachments().Upload(context.Background(), AttachmentUploadOptions{
		ItemID:   "cipher-id-1",
		FileName: "hello.txt",
		Size:     11,
		Reader:   strings.NewReader("hello world"),
	})
	require.NoError(t, err)
	assert.Equal(t, "attachment-id-1", att.ID)
	assert.Equal(t, "cipher-id-1", att.CipherID)
	assert.Equal(t, "hello.txt", att.FileName)

	// Assert recorder saw init attachment upload (POST /ciphers/.../attachment/v2).
	require.NoError(t, server.Recorder().AssertRequest("POST", "/ciphers/cipher-id-1/attachment/v2"))
	// Assert recorder saw direct content upload (POST /ciphers/.../attachment/attachment-id-1).
	require.NoError(t, server.Recorder().AssertRequest("POST", "/ciphers/cipher-id-1/attachment/attachment-id-1"))

	// Assert no raw bodies or secret values leaked — especially not
	// SECRET_ATTACHMENT_BYTES.
	require.NoError(t, server.Recorder().AssertNoRawBodies())
}

// TestPublicAttachmentDownloadContract verifies the public Attachments().Download
// flow against the testkit server. It uses mock crypto to decrypt the attachment
// key and content.
func TestPublicAttachmentDownloadContract(t *testing.T) {
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())
	identity := server.NewIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	store := mocks.NewMockTokenStore(t)

	tokenProvider := func(_ context.Context) (ports.SecretBytes, error) {
		return ports.NewSecretBytes([]byte("test-access-token")), nil
	}
	api, err := adapterhttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	require.NoError(t, err)

	// Login expectations.
	masterKey := ports.MasterKey{Bytes: []byte("deterministic-master-key")}
	userKey := ports.UserKey{Bytes: []byte("deterministic-user-key")}
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("deterministic-auth-hash"), nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, mock.Anything).Return(userKey, nil)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)

	// Download crypto expectations:
	// DecryptAttachmentKey is called with the encrypted key from the fixture.
	crypto.EXPECT().
		DecryptAttachmentKey(mock.Anything, mock.Anything, ports.EncryptedAttachment{
			ID:  "attachment-id-1",
			Key: "2.sanitized-iv|sanitized-attachment-key|sanitized-mac",
		}).
		Return(ports.AttachmentKey{Bytes: make([]byte, 64)}, nil).
		Once()

	// DecryptAttachment should read from the encrypted reader and write
	// plaintext to dst.
	crypto.EXPECT().
		DecryptAttachment(mock.Anything, mock.AnythingOfType("ports.AttachmentKey"), mock.Anything, mock.Anything).
		Return(nil).
		Run(func(_ context.Context, _ ports.AttachmentKey, _ io.Reader, dst io.Writer) {
			_, _ = dst.Write([]byte("plaintext"))
		}).
		Once()

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	_, err = client.BeginLogin(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	require.False(t, client.IsLocked())

	var dst bytes.Buffer
	err = client.Attachments().Download(context.Background(), "cipher-id-1", "attachment-id-1", &dst)
	require.NoError(t, err)
	assert.Equal(t, "plaintext", dst.String())

	// Assert recorder saw metadata GET and download GET.
	require.NoError(t, server.Recorder().AssertRequest("GET", "/ciphers/cipher-id-1/attachment/attachment-id-1"))
	require.NoError(t, server.Recorder().AssertRequest("GET", "/attachment-download/attachment-id-1"))

	// Assert no raw bodies or secret values leaked.
	require.NoError(t, server.Recorder().AssertNoRawBodies())
}

// TestPublicAttachmentDeleteContract verifies the public Attachments().Delete
// flow against the testkit server.
func TestPublicAttachmentDeleteContract(t *testing.T) {
	server := bitwardenremote.NewServer(t, bitwardenremote.NewScenario())
	identity := server.NewIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	store := mocks.NewMockTokenStore(t)

	tokenProvider := func(_ context.Context) (ports.SecretBytes, error) {
		return ports.NewSecretBytes([]byte("test-access-token")), nil
	}
	api, err := adapterhttp.NewVaultClient(server.IdentityURL(), server.HTTPClient(), tokenProvider)
	require.NoError(t, err)

	// Login expectations.
	masterKey := ports.MasterKey{Bytes: []byte("deterministic-master-key")}
	userKey := ports.UserKey{Bytes: []byte("deterministic-user-key")}
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("deterministic-auth-hash"), nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, mock.Anything).Return(userKey, nil)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	_, err = client.BeginLogin(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	require.False(t, client.IsLocked())

	err = client.Attachments().Delete(context.Background(), "cipher-id-1", "attachment-id-1")
	require.NoError(t, err)

	// Assert recorder saw the DELETE endpoint.
	require.NoError(t, server.Recorder().AssertRequest("DELETE", "/ciphers/cipher-id-1/attachment/attachment-id-1"))

	// Assert no raw bodies or secret values leaked.
	require.NoError(t, server.Recorder().AssertNoRawBodies())
}
