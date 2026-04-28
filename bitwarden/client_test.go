package bitwarden

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewClient_DefaultsToLockedUSClient(t *testing.T) {
	client := NewClient()

	require.True(t, client.IsLocked())
	require.Equal(t, RegionUS, client.region)
	require.NotNil(t, client.httpClient)
}

func TestNewClient_AppliesOptions(t *testing.T) {
	httpClient := &http.Client{}
	client := NewClient(
		WithRegion(RegionEU),
		WithBaseURL("https://example.test"),
		WithHTTPClient(httpClient),
	)

	require.Equal(t, RegionEU, client.region)
	require.Equal(t, "https://example.test", client.baseURL)
	require.Same(t, httpClient, client.httpClient)
}

func TestUnsupportedMethodsReturnSentinel(t *testing.T) {
	client := NewClient()

	require.ErrorIs(t, client.Login(context.Background(), LoginOptions{}), ErrUnsupported)
	require.ErrorIs(t, client.Sync(context.Background()), ErrUnsupported)
	_, err := client.Vault().Search(context.Background(), "github")
	require.True(t, errors.Is(err, ErrUnsupported))
}
