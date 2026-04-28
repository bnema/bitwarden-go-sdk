package bitwarden

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

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

func TestNewClient_AppliesLoggerOption(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, nil))
	client, err := NewClient(
		WithLogger(logger),
	)

	require.NoError(t, err)
	require.NotNil(t, client)
	require.Same(t, logger, client.logger)
}

func TestUnsupportedMethodsReturnSentinel(t *testing.T) {
	client, err := NewClient()
	require.NoError(t, err)

	// Sync
	err = client.Sync(context.Background())
	require.ErrorIs(t, err, ErrUnsupported)
	verifyUnsupportedError(t, err, "Client.Sync")

	// Vault.Search
	_, err = client.Vault().Search(context.Background(), "github")
	require.ErrorIs(t, err, ErrUnsupported)
	verifyUnsupportedError(t, err, "Vault.Search")

	// Vault.Get
	_, err = client.Vault().Get(context.Background(), "item-1")
	require.ErrorIs(t, err, ErrUnsupported)
	verifyUnsupportedError(t, err, "Vault.Get")

	// Vault.Password
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

func TestNewClient_WithLoggerNil_KeepsDefault(t *testing.T) {
	client, err := NewClient(WithLogger(nil))
	require.NoError(t, err)
	require.NotNil(t, client.logger)
}
