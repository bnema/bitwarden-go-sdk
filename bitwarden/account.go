package bitwarden

import (
	"context"

	coreaccount "github.com/bnema/bitwarden-go-sdk/internal/core/account"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
)

// Profile represents the public account profile.
type Profile struct {
	ID                      string
	Email                   string
	Name                    string
	EmailVerified           bool
	Premium                 bool
	PremiumFromOrganization bool
	Culture                 string
	TwoFactorEnabled        bool
	ForcePasswordReset      bool
	UsesKeyConnector        bool
	VerifyDevices           bool
}

// Subscription represents the public account subscription.
type Subscription struct {
	Plan         string
	IsPremium    bool
	StorageName  string
	StorageGB    int
	MaxStorageGB int
}

// AccountCapabilities represents derived account capabilities.
type AccountCapabilities struct {
	Premium                 bool
	PersonalPremium         bool
	PremiumFromOrganization bool
	StorageName             string
	StorageGB               int
	MaxStorageGB            int
}

// Account is the public facade for account operations.
type Account struct {
	client *Client
}

// Account returns the account facade.
func (c *Client) Account() *Account {
	return &Account{client: c}
}

func (a *Account) accountService() *coreaccount.Service {
	return coreaccount.NewService(coreaccount.Dependencies{
		API:    a.client.api,
		Locked: false,
	})
}

// Profile returns the account profile.
func (a *Account) Profile(ctx context.Context) (Profile, error) {
	if a.client.IsLocked() {
		return Profile{}, mapCoreError(&coreerrors.Error{
			Kind:    coreerrors.KindLocked,
			Op:      "Account.Profile",
			Message: "client is locked",
		})
	}

	coreProfile, err := a.accountService().Profile(ctx)
	if err != nil {
		return Profile{}, mapCoreError(err)
	}

	return mapProfile(coreProfile), nil
}

// Subscription returns the account subscription.
func (a *Account) Subscription(ctx context.Context) (Subscription, error) {
	if a.client.IsLocked() {
		return Subscription{}, mapCoreError(&coreerrors.Error{
			Kind:    coreerrors.KindLocked,
			Op:      "Account.Subscription",
			Message: "client is locked",
		})
	}

	coreSub, err := a.accountService().Subscription(ctx)
	if err != nil {
		return Subscription{}, mapCoreError(err)
	}

	return mapSubscription(coreSub), nil
}

// Capabilities returns derived account capabilities.
func (a *Account) Capabilities(ctx context.Context) (AccountCapabilities, error) {
	if a.client.IsLocked() {
		return AccountCapabilities{}, mapCoreError(&coreerrors.Error{
			Kind:    coreerrors.KindLocked,
			Op:      "Account.Capabilities",
			Message: "client is locked",
		})
	}

	caps, err := a.accountService().Capabilities(ctx)
	if err != nil {
		return AccountCapabilities{}, mapCoreError(err)
	}

	return mapCapabilities(caps), nil
}

func mapProfile(p coreaccount.Profile) Profile {
	return Profile{
		ID:                      p.ID,
		Email:                   p.Email,
		Name:                    p.Name,
		EmailVerified:           p.EmailVerified,
		Premium:                 p.Premium,
		PremiumFromOrganization: p.PremiumFromOrganization,
		Culture:                 p.Culture,
		TwoFactorEnabled:        p.TwoFactorEnabled,
		ForcePasswordReset:      p.ForcePasswordReset,
		UsesKeyConnector:        p.UsesKeyConnector,
		VerifyDevices:           p.VerifyDevices,
	}
}

func mapSubscription(s coreaccount.Subscription) Subscription {
	return Subscription{
		Plan:         s.Plan,
		IsPremium:    s.IsPremium,
		StorageName:  s.StorageName,
		StorageGB:    s.StorageGB,
		MaxStorageGB: s.MaxStorageGB,
	}
}

func mapCapabilities(c coreaccount.Capabilities) AccountCapabilities {
	return AccountCapabilities{
		Premium:                 c.Premium,
		PersonalPremium:         c.PersonalPremium,
		PremiumFromOrganization: c.PremiumFromOrganization,
		StorageName:             c.StorageName,
		StorageGB:               c.StorageGB,
		MaxStorageGB:            c.MaxStorageGB,
	}
}
