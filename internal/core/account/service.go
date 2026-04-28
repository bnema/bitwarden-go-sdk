// Package account owns core use cases for account management.
//
// Core packages must not import adapters.
package account

import (
	"context"

	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// Profile holds core account profile data.
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

// Subscription holds core subscription information.
type Subscription struct {
	Plan         string
	IsPremium    bool
	StorageName  string
	StorageGB    int
	MaxStorageGB int
}

// Capabilities holds derived account capabilities.
type Capabilities struct {
	Premium                 bool
	PersonalPremium         bool
	PremiumFromOrganization bool
	StorageName             string
	StorageGB               int
	MaxStorageGB            int
}

// Dependencies holds the service's dependencies.
type Dependencies struct {
	API    ports.APIClient
	Locked bool
}

// Service provides account use-case operations.
type Service struct {
	deps Dependencies
}

// NewService creates a new account Service.
func NewService(deps Dependencies) *Service {
	return &Service{deps: deps}
}

// Profile returns the account profile.
func (s *Service) Profile(ctx context.Context) (Profile, error) {
	if s.deps.Locked {
		return Profile{}, &coreerrors.Error{
			Kind:    coreerrors.KindLocked,
			Op:      "account.Profile",
			Message: "client is locked",
		}
	}

	p, err := s.deps.API.AccountProfile(ctx)
	if err != nil {
		return Profile{}, err
	}

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
	}, nil
}

// Subscription returns the account subscription.
func (s *Service) Subscription(ctx context.Context) (Subscription, error) {
	if s.deps.Locked {
		return Subscription{}, &coreerrors.Error{
			Kind:    coreerrors.KindLocked,
			Op:      "account.Subscription",
			Message: "client is locked",
		}
	}

	sub, err := s.deps.API.Subscription(ctx)
	if err != nil {
		return Subscription{}, err
	}

	return Subscription{
		Plan:         sub.Plan,
		IsPremium:    sub.IsPremium,
		StorageName:  sub.StorageName,
		StorageGB:    sub.StorageGB,
		MaxStorageGB: sub.MaxStorageGB,
	}, nil
}

// Capabilities returns derived account capabilities.
func (s *Service) Capabilities(ctx context.Context) (Capabilities, error) {
	if s.deps.Locked {
		return Capabilities{}, &coreerrors.Error{
			Kind:    coreerrors.KindLocked,
			Op:      "account.Capabilities",
			Message: "client is locked",
		}
	}

	sub, err := s.deps.API.Subscription(ctx)
	if err != nil {
		return Capabilities{}, err
	}

	profile, err := s.deps.API.AccountProfile(ctx)
	if err != nil {
		return Capabilities{}, err
	}

	premium := profile.Premium || profile.PremiumFromOrganization

	return Capabilities{
		Premium:                 premium,
		PersonalPremium:         profile.Premium,
		PremiumFromOrganization: profile.PremiumFromOrganization,
		StorageName:             sub.StorageName,
		StorageGB:               sub.StorageGB,
		MaxStorageGB:            sub.MaxStorageGB,
	}, nil
}
