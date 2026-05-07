// Package folders owns core use cases for folder management.
//
// Core packages must not import adapters.
package folders

import (
	"context"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/secretmem"
)

// Folder is a plaintext folder model.
type Folder struct {
	ID   string
	Name string
}

// Dependencies groups folder service dependencies.
type Dependencies struct {
	API     ports.APIClient
	Crypto  ports.CryptoEngine
	UserKey ports.UserKey
	Locked  bool
}

// Service provides folder CRUD operations with encryption/decryption.
type Service struct {
	api     ports.APIClient
	crypto  ports.CryptoEngine
	userKey ports.UserKey
	locked  bool
}

// NewService creates a folder service from Dependencies.
func NewService(deps Dependencies) *Service {
	return &Service{
		api:     deps.API,
		crypto:  deps.Crypto,
		userKey: ports.UserKey{Bytes: secretmem.Clone(deps.UserKey.Bytes)},
		locked:  deps.Locked,
	}
}

// List returns all folders with decrypted names. Returns KindLocked when
// the service is locked.
func (s *Service) List(ctx context.Context) ([]Folder, error) {
	if s.locked {
		return nil, &errors.Error{Kind: errors.KindLocked, Op: "folders.Service.List", Message: "service is locked"}
	}

	encFolders, err := s.api.ListFolders(ctx)
	if err != nil {
		return nil, err
	}

	folders := make([]Folder, 0, len(encFolders))
	for _, ef := range encFolders {
		name, err := s.crypto.DecryptFolderName(ctx, s.userKey, ef.Name)
		if err != nil {
			return nil, err
		}
		folders = append(folders, Folder{ID: ef.ID, Name: name})
	}

	return folders, nil
}

// Create creates a new folder with the given name. The name is encrypted
// before being sent to the API. Returns KindLocked when the service is locked.
func (s *Service) Create(ctx context.Context, name string) (Folder, error) {
	if s.locked {
		return Folder{}, &errors.Error{Kind: errors.KindLocked, Op: "folders.Service.Create", Message: "service is locked"}
	}

	encName, err := s.crypto.EncryptFolderName(ctx, s.userKey, name)
	if err != nil {
		return Folder{}, err
	}

	created, err := s.api.CreateFolder(ctx, ports.EncryptedFolder{Name: encName})
	if err != nil {
		return Folder{}, err
	}

	decName, err := s.crypto.DecryptFolderName(ctx, s.userKey, created.Name)
	if err != nil {
		return Folder{}, err
	}

	return Folder{ID: created.ID, Name: decName}, nil
}

// Update updates an existing folder's name. The new name is encrypted before
// being sent to the API. Returns KindLocked when the service is locked.
func (s *Service) Update(ctx context.Context, id string, name string) (Folder, error) {
	if s.locked {
		return Folder{}, &errors.Error{Kind: errors.KindLocked, Op: "folders.Service.Update", Message: "service is locked"}
	}

	encName, err := s.crypto.EncryptFolderName(ctx, s.userKey, name)
	if err != nil {
		return Folder{}, err
	}

	updated, err := s.api.UpdateFolder(ctx, id, ports.EncryptedFolder{Name: encName})
	if err != nil {
		return Folder{}, err
	}

	decName, err := s.crypto.DecryptFolderName(ctx, s.userKey, updated.Name)
	if err != nil {
		return Folder{}, err
	}

	return Folder{ID: updated.ID, Name: decName}, nil
}

// Delete deletes a folder by ID. Returns KindLocked when the service is locked.
func (s *Service) Delete(ctx context.Context, id string) error {
	if s.locked {
		return &errors.Error{Kind: errors.KindLocked, Op: "folders.Service.Delete", Message: "service is locked"}
	}

	return s.api.DeleteFolder(ctx, id)
}
