package vault

import (
	"context"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// ---------------------------------------------------------------------------
// Item → ports.Cipher mapping (reverse of cipherToItem)
// ---------------------------------------------------------------------------

func itemToPortsCipher(item Item) ports.Cipher {
	c := ports.Cipher{
		ID:       item.ID,
		Type:     item.Type,
		Name:     item.Name,
		Notes:    item.Notes,
		Favorite: item.Favorite,
		FolderID: item.FolderID,
	}

	if item.Login != nil {
		uris := make([]ports.LoginURI, len(item.Login.URIs))
		for i, u := range item.Login.URIs {
			uris[i] = ports.LoginURI{
				URI:         u.URI,
				Match:       u.Match,
				URIChecksum: u.URIChecksum,
			}
		}
		c.Login = &ports.LoginCipher{
			Username: item.Login.Username,
			Password: item.Login.Password,
			TOTP:     item.Login.TOTP,
			URIs:     uris,
		}
		// Legacy flat fields.
		c.Username = item.Login.Username
		c.Password = item.Login.Password
	}

	if item.SecureNote != nil {
		c.SecureNote = &ports.SecureNoteCipher{
			Type: item.SecureNote.Type,
		}
	}

	if item.Card != nil {
		c.Card = &ports.CardCipher{
			CardholderName: item.Card.CardholderName,
			Brand:          item.Card.Brand,
			Number:         item.Card.Number,
			ExpMonth:       item.Card.ExpMonth,
			ExpYear:        item.Card.ExpYear,
			Code:           item.Card.Code,
		}
	}

	if item.Identity != nil {
		c.Identity = &ports.IdentityCipher{
			Title:          item.Identity.Title,
			FirstName:      item.Identity.FirstName,
			MiddleName:     item.Identity.MiddleName,
			LastName:       item.Identity.LastName,
			Address1:       item.Identity.Address1,
			Address2:       item.Identity.Address2,
			Address3:       item.Identity.Address3,
			City:           item.Identity.City,
			State:          item.Identity.State,
			PostalCode:     item.Identity.PostalCode,
			Country:        item.Identity.Country,
			Company:        item.Identity.Company,
			Email:          item.Identity.Email,
			Phone:          item.Identity.Phone,
			SSN:            item.Identity.SSN,
			Username:       item.Identity.Username,
			PassportNumber: item.Identity.PassportNumber,
			LicenseNumber:  item.Identity.LicenseNumber,
		}
	}

	if item.Fields != nil {
		fields := make([]ports.CipherField, len(item.Fields))
		for i, f := range item.Fields {
			fields[i] = ports.CipherField{
				Name:     f.Name,
				Value:    f.Value,
				Type:     f.Type,
				LinkedID: f.LinkedID,
			}
		}
		c.Fields = fields
	}

	return c
}

// ---------------------------------------------------------------------------
// Snapshot helpers (caller must hold s.mu write lock)
// ---------------------------------------------------------------------------

// snapshotUpsertItem inserts or replaces an item in the snapshot by ID.
// Returns a new Snapshot; does not mutate the receiver.
func snapshotUpsertItem(s Snapshot, item Item) Snapshot {
	items := make([]Item, 0, len(s.items)+1)
	replaced := false
	for _, existing := range s.items {
		if existing.ID == item.ID {
			items = append(items, item.clone())
			replaced = true
		} else {
			items = append(items, existing)
		}
	}
	if !replaced {
		items = append(items, item.clone())
	}
	return NewSnapshot(items, s.folders)
}

// snapshotRemoveItem removes an item by ID from the snapshot.
// Returns a new Snapshot; does not mutate the receiver.
func snapshotRemoveItem(s Snapshot, id string) Snapshot {
	items := make([]Item, 0, len(s.items))
	for _, existing := range s.items {
		if existing.ID != id {
			items = append(items, existing)
		}
	}
	return NewSnapshot(items, s.folders)
}

// ---------------------------------------------------------------------------
// Cipher write operations
// ---------------------------------------------------------------------------

// CreateCipher encrypts the plaintext cipher, calls the API to create it,
// decrypts the response, and updates the local snapshot atomically on success.
func (s *Service) CreateCipher(ctx context.Context, cipher Item) (Item, error) {
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return Item{}, &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.CreateCipher", Message: "vault is locked"}
	}
	userKey := ports.UserKey{Bytes: append([]byte(nil), s.userKey.Bytes...)}
	s.mu.RUnlock()

	// Encrypt the plaintext cipher.
	enc, err := s.crypto.EncryptCipher(ctx, userKey, itemToPortsCipher(cipher))
	if err != nil {
		return Item{}, err
	}

	// Call the API.
	created, err := s.api.CreateCipher(ctx, enc)
	if err != nil {
		return Item{}, err
	}

	// Decrypt the response.
	decrypted, err := s.crypto.DecryptCipher(ctx, userKey, created)
	if err != nil {
		return Item{}, err
	}

	result := cipherToItem(decrypted)

	// Atomically update snapshot.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return Item{}, &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.CreateCipher", Message: "vault is locked"}
	}
	s.snapshot = snapshotUpsertItem(s.snapshot, result)

	return result, nil
}

// UpdateCipher encrypts the plaintext cipher, calls the API to update it,
// decrypts the response, and replaces the item in the local snapshot
// atomically on success.
func (s *Service) UpdateCipher(ctx context.Context, id string, cipher Item) (Item, error) {
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return Item{}, &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.UpdateCipher", Message: "vault is locked"}
	}
	userKey := ports.UserKey{Bytes: append([]byte(nil), s.userKey.Bytes...)}
	s.mu.RUnlock()

	// Encrypt the plaintext cipher.
	enc, err := s.crypto.EncryptCipher(ctx, userKey, itemToPortsCipher(cipher))
	if err != nil {
		return Item{}, err
	}

	// Call the API.
	updated, err := s.api.UpdateCipher(ctx, id, enc)
	if err != nil {
		return Item{}, err
	}

	// Decrypt the response.
	decrypted, err := s.crypto.DecryptCipher(ctx, userKey, updated)
	if err != nil {
		return Item{}, err
	}

	result := cipherToItem(decrypted)

	// Atomically update snapshot.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return Item{}, &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.UpdateCipher", Message: "vault is locked"}
	}
	s.snapshot = snapshotUpsertItem(s.snapshot, result)

	return result, nil
}

// TrashCipher soft-deletes (trashes) a cipher via the API and removes it
// from the local snapshot on success.
func (s *Service) TrashCipher(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.TrashCipher", Message: "vault is locked"}
	}
	s.mu.RUnlock()

	if err := s.api.TrashCipher(ctx, id); err != nil {
		return err
	}

	// Atomically remove from snapshot.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.TrashCipher", Message: "vault is locked"}
	}
	s.snapshot = snapshotRemoveItem(s.snapshot, id)

	return nil
}

// RestoreCipher restores a trashed cipher via the API, decrypts the
// response, and upserts the local snapshot on success.
func (s *Service) RestoreCipher(ctx context.Context, id string) (Item, error) {
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return Item{}, &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.RestoreCipher", Message: "vault is locked"}
	}
	userKey := ports.UserKey{Bytes: append([]byte(nil), s.userKey.Bytes...)}
	s.mu.RUnlock()

	enc, err := s.api.RestoreCipher(ctx, id)
	if err != nil {
		return Item{}, err
	}

	decrypted, err := s.crypto.DecryptCipher(ctx, userKey, enc)
	if err != nil {
		return Item{}, err
	}

	result := cipherToItem(decrypted)

	// Atomically upsert snapshot.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return Item{}, &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.RestoreCipher", Message: "vault is locked"}
	}
	s.snapshot = snapshotUpsertItem(s.snapshot, result)

	return result, nil
}

// DeleteCipher permanently deletes a cipher via the API and removes it
// from the local snapshot on success.
func (s *Service) DeleteCipher(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.DeleteCipher", Message: "vault is locked"}
	}
	s.mu.RUnlock()

	if err := s.api.DeleteCipher(ctx, id); err != nil {
		return err
	}

	// Atomically remove from snapshot.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.DeleteCipher", Message: "vault is locked"}
	}
	s.snapshot = snapshotRemoveItem(s.snapshot, id)

	return nil
}
