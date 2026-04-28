package bitwarden

import (
	"context"
	"testing"

	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAccount_Profile_Success(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)
	require.True(t, client.IsLocked())

	loginAndUnlock(t, client, identity, crypto, store)

	api.EXPECT().AccountProfile(mock.Anything).
		Return(ports.AccountProfile{
			ID:                      "user-1",
			Email:                   "user@example.com",
			Name:                    "Test User",
			EmailVerified:           true,
			Premium:                 true,
			PremiumFromOrganization: false,
			Culture:                 "en-US",
			TwoFactorEnabled:        true,
			ForcePasswordReset:      false,
			UsesKeyConnector:        false,
			VerifyDevices:           true,
		}, nil)

	profile, err := client.Account().Profile(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "user-1", profile.ID)
	assert.Equal(t, "user@example.com", profile.Email)
	assert.Equal(t, "Test User", profile.Name)
	assert.True(t, profile.EmailVerified)
	assert.True(t, profile.Premium)
	assert.False(t, profile.PremiumFromOrganization)
	assert.Equal(t, "en-US", profile.Culture)
	assert.True(t, profile.TwoFactorEnabled)
	assert.False(t, profile.ForcePasswordReset)
	assert.False(t, profile.UsesKeyConnector)
	assert.True(t, profile.VerifyDevices)
}

func TestAccount_Subscription_Success(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	loginAndUnlock(t, client, identity, crypto, store)

	api.EXPECT().Subscription(mock.Anything).
		Return(ports.Subscription{
			Plan:         "Personal",
			IsPremium:    true,
			StorageName:  "Personal",
			StorageGB:    1,
			MaxStorageGB: 1,
		}, nil)

	sub, err := client.Account().Subscription(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "Personal", sub.Plan)
	assert.True(t, sub.IsPremium)
	assert.Equal(t, "Personal", sub.StorageName)
	assert.Equal(t, 1, sub.StorageGB)
	assert.Equal(t, 1, sub.MaxStorageGB)
}

func TestAccount_Capabilities_Free(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	loginAndUnlock(t, client, identity, crypto, store)

	api.EXPECT().Subscription(mock.Anything).
		Return(ports.Subscription{
			StorageName:  "Free",
			StorageGB:    0,
			MaxStorageGB: 0,
		}, nil)
	api.EXPECT().AccountProfile(mock.Anything).
		Return(ports.AccountProfile{
			Premium:                 false,
			PremiumFromOrganization: false,
		}, nil)

	caps, err := client.Account().Capabilities(context.Background())
	require.NoError(t, err)

	assert.False(t, caps.Premium)
	assert.False(t, caps.PersonalPremium)
	assert.False(t, caps.PremiumFromOrganization)
	assert.Equal(t, "Free", caps.StorageName)
	assert.Equal(t, 0, caps.StorageGB)
	assert.Equal(t, 0, caps.MaxStorageGB)
}

func TestAccount_Capabilities_PaidPersonal(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	loginAndUnlock(t, client, identity, crypto, store)

	api.EXPECT().Subscription(mock.Anything).
		Return(ports.Subscription{
			StorageName:  "Personal",
			StorageGB:    1,
			MaxStorageGB: 1,
		}, nil)
	api.EXPECT().AccountProfile(mock.Anything).
		Return(ports.AccountProfile{
			Premium:                 true,
			PremiumFromOrganization: false,
		}, nil)

	caps, err := client.Account().Capabilities(context.Background())
	require.NoError(t, err)

	assert.True(t, caps.Premium)
	assert.True(t, caps.PersonalPremium)
	assert.False(t, caps.PremiumFromOrganization)
}

func TestAccount_Capabilities_PremiumFromOrganization(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	loginAndUnlock(t, client, identity, crypto, store)

	api.EXPECT().Subscription(mock.Anything).
		Return(ports.Subscription{
			StorageName:  "Free",
			StorageGB:    0,
			MaxStorageGB: 0,
		}, nil)
	api.EXPECT().AccountProfile(mock.Anything).
		Return(ports.AccountProfile{
			Premium:                 false,
			PremiumFromOrganization: true,
		}, nil)

	caps, err := client.Account().Capabilities(context.Background())
	require.NoError(t, err)

	assert.True(t, caps.Premium)
	assert.False(t, caps.PersonalPremium)
	assert.True(t, caps.PremiumFromOrganization)
}

func TestAccount_Profile_Unauthorized(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(
		WithIdentityClient(identity),
		WithCryptoEngine(crypto),
		WithTokenStore(store),
		WithAPIClient(api),
	)
	require.NoError(t, err)

	loginAndUnlock(t, client, identity, crypto, store)

	api.EXPECT().AccountProfile(mock.Anything).
		Return(ports.AccountProfile{}, &coreerrors.Error{
			Kind:   coreerrors.KindUnauthenticated,
			Status: 401,
		})

	_, err = client.Account().Profile(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnauthorized)
}

func TestAccount_Locked_ReturnsErrLocked(t *testing.T) {
	t.Parallel()
	client, err := NewClient()
	require.NoError(t, err)

	// Client is locked by default - no account set up
	_, err = client.Account().Profile(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLocked)

	_, err = client.Account().Subscription(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLocked)

	_, err = client.Account().Capabilities(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLocked)
}
