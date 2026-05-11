package bitwarden

import (
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/secretmem"
)

// Region identifies a Bitwarden service region.
type Region string

const (
	// RegionUS identifies the US region.
	RegionUS Region = "us"
	// RegionEU identifies the EU region.
	RegionEU Region = "eu"
)

// LoginOptions configures a master-password login attempt.
// Password is consumed to derive Bitwarden auth material and is not logged or
// persisted by the SDK.
type LoginOptions struct {
	Email                    string
	Password                 string
	DeviceType               string
	DeviceIdentifier         string
	DeviceName               string
	RememberedTwoFactorToken []byte
}

// ItemID identifies a vault item.
type ItemID string

// Field is a public custom field on a vault item.
type Field struct {
	Name     string
	Value    string
	Type     int
	LinkedID int
}

// Card is the public payment-card shape.
type Card struct {
	CardholderName string
	Brand          string
	Number         *Secret
	ExpMonth       string
	ExpYear        string
	Code           *Secret
}

// Identity is the public identity-profile shape.
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
	SSN            *Secret
	Username       string
	PassportNumber *Secret
	LicenseNumber  *Secret
}

// Item is the public vault item shape.
type Item struct {
	ID       ItemID
	Name     string
	Username string
	URI      string
	Type     ItemType

	Notes    string
	Favorite bool
	FolderID string
	Password *Secret
	TOTP     *Secret
	URIs     []string
	Fields   []Field
	Card     *Card
	Identity *Identity
}

// Folder is a public folder model.
type Folder struct {
	ID   string
	Name string
}

// TokenSet contains OAuth token fields for a single account.
// AccessToken and RefreshToken are sensitive; call Close() to zero them.
type TokenSet struct {
	AccountID                string
	AccessToken              []byte
	RefreshToken             []byte
	RememberedTwoFactorToken []byte
	TokenType                string
	ExpiresAt                time.Time
}

// Clone returns a deep copy of the TokenSet so that callers can avoid
// aliasing the original byte slices.
func (t TokenSet) Clone() TokenSet {
	c := t
	c.AccessToken = secretmem.Clone(t.AccessToken)
	c.RefreshToken = secretmem.Clone(t.RefreshToken)
	c.RememberedTwoFactorToken = secretmem.Clone(t.RememberedTwoFactorToken)
	return c
}

// Close zeros the backing arrays of AccessToken and RefreshToken, then nils
// them. It is idempotent.
func (t *TokenSet) Close() {
	secretmem.Zero(t.AccessToken)
	t.AccessToken = nil
	secretmem.Zero(t.RefreshToken)
	t.RefreshToken = nil
	secretmem.Zero(t.RememberedTwoFactorToken)
	t.RememberedTwoFactorToken = nil
}

// SessionMaterial holds the user key and token set after a successful login.
// UserKey and Tokens.AccessToken / Tokens.RefreshToken are sensitive.
type SessionMaterial struct {
	AccountID string
	UserKey   []byte
	Tokens    TokenSet
}

// Clone returns a deep copy of the SessionMaterial so that callers can avoid
// aliasing the original byte slices.
func (m SessionMaterial) Clone() SessionMaterial {
	c := m
	c.UserKey = secretmem.Clone(m.UserKey)
	c.Tokens = m.Tokens.Clone()
	return c
}

// Close zeros the backing array of UserKey, nils it, and closes Tokens.
// It is idempotent.
func (m *SessionMaterial) Close() {
	secretmem.Zero(m.UserKey)
	m.UserKey = nil
	m.Tokens.Close()
}

// RefreshResult holds the token set returned after a token refresh.
type RefreshResult struct {
	Tokens TokenSet
}

// ItemType identifies the kind of vault item.
type ItemType string

const (
	// ItemTypeLogin identifies a login item.
	ItemTypeLogin ItemType = "login"
	// ItemTypeSecureNote identifies a secure note item.
	ItemTypeSecureNote ItemType = "secure_note"
	// ItemTypeCard identifies a payment card item.
	ItemTypeCard ItemType = "card"
	// ItemTypeIdentity identifies an identity profile item.
	ItemTypeIdentity ItemType = "identity"
)
