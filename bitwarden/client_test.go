package bitwarden

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewClient_DefaultsToLockedUSClient(t *testing.T) {
	client, err := NewClient()

	require.NoError(t, err)
	require.True(t, client.IsLocked())
	require.NotNil(t, client.httpClient)
	require.NotNil(t, client.identity)

	require.Equal(t, "https://vault.bitwarden.com", client.environment.WebVault)
	require.Equal(t, "https://api.bitwarden.com", client.environment.API)
	require.Equal(t, "https://identity.bitwarden.com", client.environment.Identity)
	require.Equal(t, "https://icons.bitwarden.net", client.environment.Icons)
}

func TestNewClient_AppliesHTTPClientOption(t *testing.T) {
	httpClient := &http.Client{}
	client, err := NewClient(
		WithHTTPClient(httpClient),
	)

	require.NoError(t, err)
	require.NotNil(t, client)
	require.Same(t, httpClient, client.httpClient)
}

func TestDefaultClientIsLocked(t *testing.T) {
	client, err := NewClient()
	require.NoError(t, err)

	// Sync returns ErrLocked when client is locked.
	err = client.Sync(context.Background())
	require.ErrorIs(t, err, ErrLocked)

	// Vault methods still return ErrLocked on a locked client without account
	// (the hasAccount check returns false, so the vault service check fires).
	_, err = client.Vault().List(context.Background())
	require.ErrorIs(t, err, ErrLocked)

	_, err = client.Vault().Search(context.Background(), "github")
	require.ErrorIs(t, err, ErrLocked)

	_, err = client.Vault().Get(context.Background(), "item-1")
	require.ErrorIs(t, err, ErrLocked)

	// Vault.Password remains unsupported.
	_, err = client.Vault().Password(context.Background(), "item-1")
	require.ErrorIs(t, err, ErrUnsupported)
	verifyUnsupportedError(t, err, "Vault.Password")
}

// verifyUnsupportedError asserts the error satisfies errors.As(*Error) and
// exposes ErrorKindUnsupported with the expected Op field.
func verifyUnsupportedError(t *testing.T, err error, expectedOp string) {
	t.Helper()
	var pubErr *Error
	require.ErrorAs(t, err, &pubErr, "errors.As should succeed for %s", expectedOp)
	require.Equal(t, ErrorKindUnsupported, pubErr.Kind, "Kind should be ErrorKindUnsupported for %s", expectedOp)
	require.Equal(t, expectedOp, pubErr.Op, "Op should be %q", expectedOp)
	require.NotEmpty(t, pubErr.Message, "Message should not be empty for %s", expectedOp)
}

func TestNewClient_WithRegionEU_ReturnsEUServerURLs(t *testing.T) {
	client, err := NewClient(WithRegion(RegionEU))
	require.NoError(t, err)
	require.NotNil(t, client)
	require.True(t, client.IsLocked())

	require.Equal(t, "https://vault.bitwarden.eu", client.environment.WebVault)
	require.Equal(t, "https://api.bitwarden.eu", client.environment.API)
	require.Equal(t, "https://identity.bitwarden.eu", client.environment.Identity)
	require.Equal(t, "https://icons.bitwarden.eu", client.environment.Icons)
	require.Equal(t, "https://scim.bitwarden.eu/v2", client.environment.SCIM)
}

func TestNewClient_WithServerURL_ReturnsSelfHostedURLs(t *testing.T) {
	client, err := NewClient(WithServerURL("https://bitwarden.example.com/"))
	require.NoError(t, err)
	require.NotNil(t, client)
	require.True(t, client.IsLocked())

	require.Equal(t, "https://bitwarden.example.com", client.environment.WebVault)
	require.Equal(t, "https://bitwarden.example.com/api", client.environment.API)
	require.Equal(t, "https://bitwarden.example.com/identity", client.environment.Identity)
	require.Equal(t, "https://bitwarden.example.com/icons", client.environment.Icons)
	require.Equal(t, "https://bitwarden.example.com/notifications", client.environment.Notifications)
	require.Equal(t, "https://bitwarden.example.com/events", client.environment.Events)
	require.Equal(t, "https://bitwarden.example.com/scim/v2", client.environment.SCIM)
	require.Equal(t, "https://bitwarden.example.com/#/send/", client.environment.Send)
}

func TestNewClient_UnknownRegion_ReturnsError(t *testing.T) {
	_, err := NewClient(WithRegion(Region("unknown")))
	require.Error(t, err)
}

func TestNewClient_WithServerURLInvalidHTTP_ReturnsError(t *testing.T) {
	_, err := NewClient(WithServerURL("http://bitwarden.example.com"))
	require.Error(t, err)
}

func TestNewClient_BothRegionAndServerURL_ReturnsError(t *testing.T) {
	_, err := NewClient(WithRegion(RegionEU), WithServerURL("https://bitwarden.example.com/"))
	require.Error(t, err)
}

func TestNewClient_WithHTTPClientNil_KeepsDefault(t *testing.T) {
	client, err := NewClient(WithHTTPClient(nil))
	require.NoError(t, err)
	require.NotNil(t, client.httpClient)
}

func TestWithTokenStoreSavesLoginTokens(t *testing.T) {
	store := &publicTokenStoreStub{}
	identity := mocks.NewMockIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	masterKey := ports.MasterKey{Bytes: []byte("master")}
	userKey := ports.UserKey{Bytes: []byte("user")}
	tokens := ports.TokenSet{
		AccountID:    "account-1",
		AccessToken:  ports.NewSecretBytes([]byte("access")),
		RefreshToken: ports.NewSecretBytes([]byte("refresh")),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, mock.MatchedBy(func(req ports.PasswordTokenRequest) bool {
		return req.DeviceType != "" && req.DeviceIdentifier != "" && req.DeviceName != ""
	})).Return(ports.TokenResponse{Tokens: tokens, AccountID: "account-1", EncryptedUserKey: "enc-user"}, nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, ports.UserKeyInput{MasterKey: masterKey, EncryptedUserKey: "enc-user"}).Return(userKey, nil)

	client, err := NewClient(
		withIdentityClient(identity),
		withCryptoEngine(crypto),
		WithTokenStore(store),
	)
	require.NoError(t, err)

	result, err := client.BeginLogin(context.Background(), LoginOptions{
		Email:            "alice@example.com",
		Password:         "password",
		DeviceType:       "LinuxDesktop",
		DeviceIdentifier: "device-1",
		DeviceName:       "test-device",
	})
	require.NoError(t, err)
	assert.Equal(t, "account-1", result.AccountID)
	assert.False(t, client.IsLocked())

	require.True(t, store.savedCalled, "SaveTokens should have been called on the store")
	assert.Equal(t, "account-1", store.saved.AccountID)
	assert.Equal(t, []byte("access"), store.saved.AccessToken)
	assert.Equal(t, []byte("refresh"), store.saved.RefreshToken)
}

// publicTokenStoreStub is a test-only implementation of the public TokenStore
// that captures the last saved token set in memory.
type publicTokenStoreStub struct {
	mu          sync.Mutex
	saved       TokenSet
	savedCalled bool
}

func (s *publicTokenStoreStub) SaveTokens(_ context.Context, tokens TokenSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saved = tokens.Clone()
	s.savedCalled = true
	return nil
}

func (s *publicTokenStoreStub) LoadTokens(_ context.Context, _ string) (TokenSet, error) {
	return TokenSet{}, errors.New("unexpected LoadTokens call")
}

func (s *publicTokenStoreStub) DeleteTokens(_ context.Context, _ string) error {
	return nil
}
