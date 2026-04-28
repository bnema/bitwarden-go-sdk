package account_test

import (
	"context"
	"testing"

	coreaccount "github.com/bnema/bitwarden-go-sdk/internal/core/account"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccount_Profile_Success(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)

	api.EXPECT().AccountProfile(ctx()).
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

	svc := coreaccount.NewService(coreaccount.Dependencies{API: api})
	profile, err := svc.Profile(context.Background())
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

	api.EXPECT().Subscription(ctx()).
		Return(ports.Subscription{
			Plan:         "Personal",
			IsPremium:    true,
			StorageName:  "Personal",
			StorageGB:    1,
			MaxStorageGB: 1,
		}, nil)

	svc := coreaccount.NewService(coreaccount.Dependencies{API: api})
	sub, err := svc.Subscription(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "Personal", sub.Plan)
	assert.True(t, sub.IsPremium)
	assert.Equal(t, "Personal", sub.StorageName)
	assert.Equal(t, 1, sub.StorageGB)
	assert.Equal(t, 1, sub.MaxStorageGB)
}

func TestAccount_Capabilities_FreeAccount(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)

	api.EXPECT().Subscription(ctx()).
		Return(ports.Subscription{
			StorageName:  "Free",
			StorageGB:    0,
			MaxStorageGB: 0,
		}, nil)
	api.EXPECT().AccountProfile(ctx()).
		Return(ports.AccountProfile{
			Premium:                 false,
			PremiumFromOrganization: false,
		}, nil)

	svc := coreaccount.NewService(coreaccount.Dependencies{API: api})
	caps, err := svc.Capabilities(context.Background())
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

	api.EXPECT().Subscription(ctx()).
		Return(ports.Subscription{
			StorageName:  "Personal",
			StorageGB:    1,
			MaxStorageGB: 1,
		}, nil)
	api.EXPECT().AccountProfile(ctx()).
		Return(ports.AccountProfile{
			Premium:                 true,
			PremiumFromOrganization: false,
		}, nil)

	svc := coreaccount.NewService(coreaccount.Dependencies{API: api})
	caps, err := svc.Capabilities(context.Background())
	require.NoError(t, err)

	assert.True(t, caps.Premium)
	assert.True(t, caps.PersonalPremium)
	assert.False(t, caps.PremiumFromOrganization)
	assert.Equal(t, "Personal", caps.StorageName)
	assert.Equal(t, 1, caps.StorageGB)
	assert.Equal(t, 1, caps.MaxStorageGB)
}

func TestAccount_Capabilities_PremiumFromOrganization(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)

	api.EXPECT().Subscription(ctx()).
		Return(ports.Subscription{
			StorageName:  "Free",
			StorageGB:    0,
			MaxStorageGB: 0,
		}, nil)
	api.EXPECT().AccountProfile(ctx()).
		Return(ports.AccountProfile{
			Premium:                 false,
			PremiumFromOrganization: true,
		}, nil)

	svc := coreaccount.NewService(coreaccount.Dependencies{API: api})
	caps, err := svc.Capabilities(context.Background())
	require.NoError(t, err)

	assert.True(t, caps.Premium)
	assert.False(t, caps.PersonalPremium)
	assert.True(t, caps.PremiumFromOrganization)
}

func TestAccount_Capabilities_Unauthorized(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)

	api.EXPECT().Subscription(ctx()).
		Return(ports.Subscription{}, &coreerrors.Error{
			Kind:   coreerrors.KindUnauthenticated,
			Status: 401,
		})

	svc := coreaccount.NewService(coreaccount.Dependencies{API: api})
	_, err := svc.Capabilities(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, &coreerrors.Error{Kind: coreerrors.KindUnauthenticated})
}

func TestAccount_Profile_Locked(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)

	svc := coreaccount.NewService(coreaccount.Dependencies{
		API:    api,
		Locked: true,
	})

	_, err := svc.Profile(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, &coreerrors.Error{Kind: coreerrors.KindLocked})
}

func TestAccount_Subscription_Locked(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)

	svc := coreaccount.NewService(coreaccount.Dependencies{
		API:    api,
		Locked: true,
	})

	_, err := svc.Subscription(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, &coreerrors.Error{Kind: coreerrors.KindLocked})
}

func TestAccount_Capabilities_Locked(t *testing.T) {
	t.Parallel()
	api := mocks.NewMockAPIClient(t)

	svc := coreaccount.NewService(coreaccount.Dependencies{
		API:    api,
		Locked: true,
	})

	_, err := svc.Capabilities(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, &coreerrors.Error{Kind: coreerrors.KindLocked})
}

// Helper to get a cancellable context for mocks
func ctx() context.Context {
	return context.Background()
}
