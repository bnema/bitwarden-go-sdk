package dto

// ---------------------------------------------------------------------------
// Sync response
// ---------------------------------------------------------------------------

// SyncResponseDTO maps the Bitwarden /sync response body.
type SyncResponseDTO struct {
	Profile  ProfileDTO  `json:"Profile"`
	Folders  []FolderDTO `json:"Folders"`
	Ciphers  []CipherDTO `json:"Ciphers"`
	Domains  any         `json:"Domains"`
	Policies []any       `json:"Policies"`
	Sends    []any       `json:"Sends"`
}

// ProfileDTO maps the Profile object inside a sync response.
type ProfileDTO struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Email string `json:"Email"`
}

// FolderDTO maps a folder object.
type FolderDTO struct {
	ID   string `json:"Id"`
	Name string `json:"Name"`
}

// CipherDTO maps a cipher object in a sync response.
type CipherDTO struct {
	ID         string         `json:"Id"`
	Type       int            `json:"Type"`
	Name       string         `json:"Name"`
	Notes      *string        `json:"Notes,omitempty"`
	Favorite   bool           `json:"Favorite"`
	FolderID   *string        `json:"FolderId,omitempty"`
	Login      *LoginDTO      `json:"Login,omitempty"`
	SecureNote *SecureNoteDTO `json:"SecureNote,omitempty"`
	Card       *CardDTO       `json:"Card,omitempty"`
	Identity   *IdentityDTO   `json:"Identity,omitempty"`
	Fields     []FieldDTO     `json:"Fields,omitempty"`
}

// LoginDTO maps the Login sub-object of a cipher.
type LoginDTO struct {
	Username string        `json:"Username"`
	Password string        `json:"Password"`
	TOTP     string        `json:"Totp"`
	URIs     []LoginURIDTO `json:"Uris"`
}

// LoginURIDTO maps a URI entry within a login cipher.
type LoginURIDTO struct {
	URI         string `json:"Uri"`
	Match       *int   `json:"Match,omitempty"`
	URIChecksum string `json:"UriChecksum,omitempty"`
}

// SecureNoteDTO maps the SecureNote sub-object of a cipher.
type SecureNoteDTO struct {
	Type int `json:"Type"`
}

// CardDTO maps the Card sub-object of a cipher.
type CardDTO struct {
	CardholderName string `json:"CardholderName"`
	Brand          string `json:"Brand"`
	Number         string `json:"Number"`
	ExpMonth       string `json:"ExpMonth"`
	ExpYear        string `json:"ExpYear"`
	Code           string `json:"Code"`
}

// IdentityDTO maps the Identity sub-object of a cipher.
type IdentityDTO struct {
	Title          string `json:"Title"`
	FirstName      string `json:"FirstName"`
	MiddleName     string `json:"MiddleName"`
	LastName       string `json:"LastName"`
	Address1       string `json:"Address1"`
	Address2       string `json:"Address2"`
	Address3       string `json:"Address3"`
	City           string `json:"City"`
	State          string `json:"State"`
	PostalCode     string `json:"PostalCode"`
	Country        string `json:"Country"`
	Company        string `json:"Company"`
	Email          string `json:"Email"`
	Phone          string `json:"Phone"`
	SSN            string `json:"SSN"`
	Username       string `json:"Username"`
	PassportNumber string `json:"PassportNumber"`
	LicenseNumber  string `json:"LicenseNumber"`
}

// FieldDTO maps a custom field within a cipher.
type FieldDTO struct {
	Name     string `json:"Name"`
	Value    string `json:"Value"`
	Type     int    `json:"Type"`
	LinkedID int    `json:"LinkedId,omitempty"`
}

// ---------------------------------------------------------------------------
// Config response (GET /config)
// ---------------------------------------------------------------------------

// ConfigResponseDTO maps the /config endpoint response.
type ConfigResponseDTO struct {
	Version      string          `json:"version"`
	FeatureFlags map[string]bool `json:"featureFlags"`
	ServerName   string          `json:"serverName,omitempty"`
}

// ---------------------------------------------------------------------------
// Account profile (GET /accounts/profile)
// ---------------------------------------------------------------------------

// AccountProfileResponseDTO maps the /accounts/profile response.
type AccountProfileResponseDTO struct {
	ID    string `json:"Id"`
	Email string `json:"Email"`
	Name  string `json:"Name"`
}

// ---------------------------------------------------------------------------
// Subscription (GET /plans/subscription or /accounts/subscription)
// ---------------------------------------------------------------------------

// SubscriptionResponseDTO maps the subscription endpoint response.
type SubscriptionResponseDTO struct {
	Plan      string `json:"plan,omitempty"`
	IsPremium *bool  `json:"isPremium,omitempty"`
	// Bitwarden API doesn't have plan/isPremium in subscription, so
	// we map from StorageName / customer discount field as available.
	StorageName string `json:"StorageName"`
}

// ---------------------------------------------------------------------------
// Error response
// ---------------------------------------------------------------------------

// ErrorResponseDTO is a minimal error body for non-token endpoints.
type ErrorResponseDTO struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
