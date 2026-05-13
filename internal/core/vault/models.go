// Package vault owns core use cases for vault operations.
//
// Core packages must not import adapters.
package vault

import (
	"context"
	"maps"
	"strings"
	"sync"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/secretmem"
)

// Item type constants.
const (
	TypeLogin      = 1
	TypeSecureNote = 2
	TypeCard       = 3
	TypeIdentity   = 4
)

const defaultDecryptWorkers = 4

// URI represents a login URI with match detection metadata.
type URI struct {
	URI         string
	Match       int
	URIChecksum string
}

func (u URI) clone() URI {
	return URI{
		URI:         u.URI,
		Match:       u.Match,
		URIChecksum: u.URIChecksum,
	}
}

// Login holds login-specific item data.
type Login struct {
	Username string
	Password string
	TOTP     string
	URIs     []URI
}

func (l Login) clone() Login {
	uris := make([]URI, len(l.URIs))
	for i, u := range l.URIs {
		uris[i] = u.clone()
	}
	return Login{
		Username: l.Username,
		Password: l.Password,
		TOTP:     l.TOTP,
		URIs:     uris,
	}
}

// SecureNote holds secure-note type metadata.
type SecureNote struct {
	Type int
}

func (s SecureNote) clone() SecureNote {
	return SecureNote{Type: s.Type}
}

// Card holds payment-card item data.
type Card struct {
	CardholderName string
	Brand          string
	Number         string
	ExpMonth       string
	ExpYear        string
	Code           string
}

func (c Card) clone() Card {
	return Card{
		CardholderName: c.CardholderName,
		Brand:          c.Brand,
		Number:         c.Number,
		ExpMonth:       c.ExpMonth,
		ExpYear:        c.ExpYear,
		Code:           c.Code,
	}
}

// Identity holds identity-profile item data.
type Identity struct {
	Title          string
	FirstName      string
	MiddleName     string
	LastName       string
	Address1       string
	Address2       string
	Address3       string
	City           string
	State          string
	PostalCode     string
	Country        string
	Company        string
	Email          string
	Phone          string
	SSN            string
	Username       string
	PassportNumber string
	LicenseNumber  string
}

func (i Identity) clone() Identity {
	return Identity{
		Title:          i.Title,
		FirstName:      i.FirstName,
		MiddleName:     i.MiddleName,
		LastName:       i.LastName,
		Address1:       i.Address1,
		Address2:       i.Address2,
		Address3:       i.Address3,
		City:           i.City,
		State:          i.State,
		PostalCode:     i.PostalCode,
		Country:        i.Country,
		Company:        i.Company,
		Email:          i.Email,
		Phone:          i.Phone,
		SSN:            i.SSN,
		Username:       i.Username,
		PassportNumber: i.PassportNumber,
		LicenseNumber:  i.LicenseNumber,
	}
}

// Field represents a custom field on an item.
type Field struct {
	Name     string
	Value    string
	Type     int
	LinkedID int
}

func (f Field) clone() Field {
	return Field{
		Name:     f.Name,
		Value:    f.Value,
		Type:     f.Type,
		LinkedID: f.LinkedID,
	}
}

// Item represents a single vault item (cipher).
type Item struct {
	ID         string
	Type       int
	Name       string
	Notes      string
	Favorite   bool
	FolderID   string
	Login      *Login
	SecureNote *SecureNote
	Card       *Card
	Identity   *Identity
	Fields     []Field
}

func (i Item) clone() Item {
	fields := make([]Field, len(i.Fields))
	for j, f := range i.Fields {
		fields[j] = f.clone()
	}
	var login *Login
	if i.Login != nil {
		v := i.Login.clone()
		login = &v
	}
	var secureNote *SecureNote
	if i.SecureNote != nil {
		v := i.SecureNote.clone()
		secureNote = &v
	}
	var card *Card
	if i.Card != nil {
		v := i.Card.clone()
		card = &v
	}
	var identity *Identity
	if i.Identity != nil {
		v := i.Identity.clone()
		identity = &v
	}
	return Item{
		ID:         i.ID,
		Type:       i.Type,
		Name:       i.Name,
		Notes:      i.Notes,
		Favorite:   i.Favorite,
		FolderID:   i.FolderID,
		Login:      login,
		SecureNote: secureNote,
		Card:       card,
		Identity:   identity,
		Fields:     fields,
	}
}

// Snapshot is an immutable-ish view of a vault. List, Get, and Search
// return copies so callers cannot mutate internal state.
type Snapshot struct {
	items   []Item
	folders map[string]string
}

// NewSnapshot creates a Snapshot from items and a folder-id-to-name map.
func NewSnapshot(items []Item, folders map[string]string) Snapshot {
	itemsCopy := make([]Item, len(items))
	for i, item := range items {
		itemsCopy[i] = item.clone()
	}
	foldersCopy := make(map[string]string, len(folders))
	maps.Copy(foldersCopy, folders)
	return Snapshot{items: itemsCopy, folders: foldersCopy}
}

// List returns a copy of every item in the snapshot.
func (s Snapshot) List() []Item {
	result := make([]Item, len(s.items))
	for i, item := range s.items {
		result[i] = item.clone()
	}
	return result
}

// Get returns a copy of the item with the given ID and true, or false if not found.
func (s Snapshot) Get(id string) (Item, bool) {
	for _, item := range s.items {
		if item.ID == id {
			return item.clone(), true
		}
	}
	return Item{}, false
}

// Search returns copies of items whose safe fields contain query (case-insensitive).
// Safe fields are: Name, Username, URI, Notes, custom field Name/Value, and folder name.
// Password and TOTP are never searched.
func (s Snapshot) Search(query string) []Item {
	if query == "" {
		return nil
	}
	q := strings.ToLower(query)
	var results []Item
	for _, item := range s.items {
		if matchesSafe(item, q, s.folders) {
			results = append(results, item.clone())
		}
	}
	return results
}

func matchesSafe(item Item, q string, folders map[string]string) bool {
	if strings.Contains(strings.ToLower(item.Name), q) {
		return true
	}
	if strings.Contains(strings.ToLower(item.Notes), q) {
		return true
	}
	if item.Login != nil && strings.Contains(strings.ToLower(item.Login.Username), q) {
		return true
	}
	if item.Login != nil {
		for _, uri := range item.Login.URIs {
			if strings.Contains(strings.ToLower(uri.URI), q) {
				return true
			}
		}
	}
	for _, field := range item.Fields {
		if strings.Contains(strings.ToLower(field.Name), q) {
			return true
		}
		if strings.Contains(strings.ToLower(field.Value), q) {
			return true
		}
	}
	if item.FolderID != "" {
		if name, ok := folders[item.FolderID]; ok {
			if strings.Contains(strings.ToLower(name), q) {
				return true
			}
		}
	}
	return false
}

// Dependencies groups vault service dependencies.
type Dependencies struct {
	API            ports.APIClient
	Crypto         ports.CryptoEngine
	UserKey        ports.UserKey
	Locked         bool
	DecryptWorkers int
}

// Service provides read access to a vault with a locked-state guard.
type Service struct {
	mu       sync.RWMutex
	locked   bool
	snapshot Snapshot

	api            ports.APIClient
	crypto         ports.CryptoEngine
	userKey        ports.UserKey
	decryptWorkers int
}

// NewService creates a Service. It accepts zero or one Dependencies argument.
// When called with no arguments the service is created unlocked with no snapshot
// (backward compatible). When called with Dependencies the service initialises
// API, crypto, user key and lock state from the struct.
func NewService(deps ...Dependencies) *Service {
	svc := &Service{
		decryptWorkers: defaultDecryptWorkers,
	}
	if len(deps) > 0 {
		d := deps[0]
		svc.api = d.API
		svc.crypto = d.Crypto
		svc.userKey = d.UserKey
		svc.locked = d.Locked
		if d.DecryptWorkers > 0 {
			svc.decryptWorkers = d.DecryptWorkers
		}
	}
	return svc
}

// List returns all items or a locked error when the vault is locked.
func (s *Service) List() ([]Item, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.locked {
		return nil, &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.List", Message: "vault is locked"}
	}
	return s.snapshot.List(), nil
}

// Get returns an item copy by ID or a locked error when the vault is locked.
func (s *Service) Get(id string) (Item, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.locked {
		return Item{}, false, &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.Get", Message: "vault is locked"}
	}
	item, ok := s.snapshot.Get(id)
	return item, ok, nil
}

// Search returns matching item copies or a locked error when the vault is locked.
func (s *Service) Search(query string) ([]Item, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.locked {
		return nil, &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.Search", Message: "vault is locked"}
	}
	return s.snapshot.Search(query), nil
}

// Sync fetches encrypted vault data from the server, decrypts it, and
// atomically replaces the in-memory snapshot. Returns KindLocked when
// the vault is locked.
func (s *Service) Sync(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.Sync", Message: "vault is locked"}
	}
	userKey := ports.UserKey{Bytes: secretmem.Clone(s.userKey.Bytes)}
	s.mu.RUnlock()
	defer userKey.Close()

	result, err := s.api.Sync(ctx, ports.SyncOptions{})
	if err != nil {
		return err
	}

	// Decrypt folders.
	folders := make(map[string]string, len(result.Folders))
	for _, f := range result.Folders {
		name, err := s.crypto.DecryptFolderName(ctx, userKey, f.Name)
		if err != nil {
			return err
		}
		folders[f.ID] = name
	}

	// Decrypt ciphers with bounded worker pool. Organization ciphers still
	// require organization-key support, so skip them instead of failing the
	// whole personal-vault sync. Personal ciphers with wrapped per-item keys
	// are handled by the crypto engine.
	items, err := s.decryptCiphers(ctx, userKey, filterDecryptableCiphers(result.Ciphers))
	if err != nil {
		return err
	}

	// Atomically replace snapshot only if the vault is still unlocked. Lock/Clear
	// may run while API/decrypt work is in flight; in that case plaintext must
	// not be installed into service state.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return &errors.Error{Kind: errors.KindLocked, Op: "vault.Service.Sync", Message: "vault is locked"}
	}
	s.snapshot = NewSnapshot(items, folders)

	return nil
}

// decryptCiphers processes encrypted ciphers using a bounded worker pool.
func filterDecryptableCiphers(ciphers []ports.EncryptedCipher) []ports.EncryptedCipher {
	if len(ciphers) == 0 {
		return nil
	}
	out := make([]ports.EncryptedCipher, 0, len(ciphers))
	for _, cipher := range ciphers {
		if cipher.OrganizationID != "" {
			continue
		}
		out = append(out, cipher)
	}
	return out
}

func (s *Service) decryptCiphers(ctx context.Context, userKey ports.UserKey, encrypted []ports.EncryptedCipher) ([]Item, error) {
	n := len(encrypted)
	if n == 0 {
		return nil, nil
	}

	type jobResult struct {
		idx  int
		item Item
		err  error
	}

	numWorkers := s.decryptWorkers
	if numWorkers <= 0 {
		numWorkers = defaultDecryptWorkers
	}
	if numWorkers > n {
		numWorkers = n
	}

	jobs := make(chan int, n)
	results := make(chan jobResult, n)

	// Start workers.
	var wg sync.WaitGroup
	for range numWorkers {
		wg.Go(func() {
			for idx := range jobs {
				// Check cancellation before each decrypt.
				if err := ctx.Err(); err != nil {
					results <- jobResult{idx: idx, err: err}
					return
				}
				dec, err := s.crypto.DecryptCipher(ctx, userKey, encrypted[idx])
				if err != nil {
					results <- jobResult{idx: idx, err: err}
					return
				}
				results <- jobResult{idx: idx, item: cipherToItem(dec)}
			}
		})
	}

	// Send all jobs.
	for i := range n {
		jobs <- i
	}
	close(jobs)

	// Wait for all workers to finish.
	wg.Wait()
	close(results)

	// Collect results in order.
	items := make([]Item, n)
	for r := range results {
		if r.err != nil {
			return nil, r.err
		}
		items[r.idx] = r.item
	}

	return items, nil
}

// cipherToItem maps a decrypted ports.Cipher to a vault.Item.
func cipherToItem(c ports.Cipher) Item {
	item := Item{
		ID:       c.ID,
		Type:     c.Type,
		Name:     c.Name,
		Notes:    c.Notes,
		Favorite: c.Favorite,
		FolderID: c.FolderID,
	}

	if c.Login != nil {
		uris := make([]URI, len(c.Login.URIs))
		for i, u := range c.Login.URIs {
			uris[i] = URI{
				URI:         u.URI,
				Match:       u.Match,
				URIChecksum: u.URIChecksum,
			}
		}
		l := &Login{
			Username: c.Login.Username,
			Password: c.Login.Password,
			TOTP:     c.Login.TOTP,
			URIs:     uris,
		}
		item.Login = l
	}

	if c.SecureNote != nil {
		item.SecureNote = &SecureNote{Type: c.SecureNote.Type}
	}

	if c.Card != nil {
		item.Card = &Card{
			CardholderName: c.Card.CardholderName,
			Brand:          c.Card.Brand,
			Number:         c.Card.Number,
			ExpMonth:       c.Card.ExpMonth,
			ExpYear:        c.Card.ExpYear,
			Code:           c.Card.Code,
		}
	}

	if c.Identity != nil {
		item.Identity = &Identity{
			Title:          c.Identity.Title,
			FirstName:      c.Identity.FirstName,
			MiddleName:     c.Identity.MiddleName,
			LastName:       c.Identity.LastName,
			Address1:       c.Identity.Address1,
			Address2:       c.Identity.Address2,
			Address3:       c.Identity.Address3,
			City:           c.Identity.City,
			State:          c.Identity.State,
			PostalCode:     c.Identity.PostalCode,
			Country:        c.Identity.Country,
			Company:        c.Identity.Company,
			Email:          c.Identity.Email,
			Phone:          c.Identity.Phone,
			SSN:            c.Identity.SSN,
			Username:       c.Identity.Username,
			PassportNumber: c.Identity.PassportNumber,
			LicenseNumber:  c.Identity.LicenseNumber,
		}
	}

	if c.Fields != nil {
		fields := make([]Field, len(c.Fields))
		for i, f := range c.Fields {
			fields[i] = Field{
				Name:     f.Name,
				Value:    f.Value,
				Type:     f.Type,
				LinkedID: f.LinkedID,
			}
		}
		item.Fields = fields
	}

	return item
}

// SetLocked sets the locked state of the vault.
func (s *Service) SetLocked(locked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locked = locked
}

// SetUserKey sets the user key used for decryption.
func (s *Service) SetUserKey(key ports.UserKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userKey.Close()
	s.userKey = ports.UserKey{Bytes: secretmem.Clone(key.Bytes)}
}

// Clear locks the vault, zeros the user key, and replaces the snapshot with
// an empty one. It is safe to call on a nil receiver.
func (s *Service) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locked = true
	s.snapshot = Snapshot{}
	s.userKey.Close()
}
