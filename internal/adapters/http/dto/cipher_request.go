package dto

// ---------------------------------------------------------------------------
// Cipher request DTOs — lower-camel JSON tags for request bodies.
// ---------------------------------------------------------------------------

// CipherRequestDTO is sent in POST /ciphers and PUT /ciphers/{id} request bodies.
type CipherRequestDTO struct {
	Type           int                   `json:"type"`
	FolderID       *string               `json:"folderId,omitempty"`
	OrganizationID *string               `json:"organizationId,omitempty"`
	Name           string                `json:"name"`
	Notes          *string               `json:"notes,omitempty"`
	Favorite       bool                  `json:"favorite"`
	Login          *LoginRequestDTO      `json:"login,omitempty"`
	SecureNote     *SecureNoteRequestDTO `json:"secureNote,omitempty"`
	Card           *CardRequestDTO       `json:"card,omitempty"`
	Identity       *IdentityRequestDTO   `json:"identity,omitempty"`
	Fields         []FieldRequestDTO     `json:"fields,omitempty"`
	Reprompt       int                   `json:"reprompt,omitempty"`
	Key            *string               `json:"key,omitempty"`
}

// LoginRequestDTO maps the Login sub-object in a cipher request.
type LoginRequestDTO struct {
	Username string               `json:"username,omitempty"`
	Password string               `json:"password,omitempty"`
	TOTP     string               `json:"totp,omitempty"`
	URIs     []LoginURIRequestDTO `json:"uris,omitempty"`
}

// LoginURIRequestDTO maps a URI entry within a login cipher request.
type LoginURIRequestDTO struct {
	URI         string `json:"uri"`
	Match       *int   `json:"match,omitempty"`
	URIChecksum string `json:"uriChecksum,omitempty"`
}

// SecureNoteRequestDTO maps the SecureNote sub-object in a cipher request.
type SecureNoteRequestDTO struct {
	Type int `json:"type"`
}

// CardRequestDTO maps the Card sub-object in a cipher request.
type CardRequestDTO struct {
	CardholderName string `json:"cardholderName"`
	Brand          string `json:"brand"`
	Number         string `json:"number"`
	ExpMonth       string `json:"expMonth"`
	ExpYear        string `json:"expYear"`
	Code           string `json:"code"`
}

// IdentityRequestDTO maps the Identity sub-object in a cipher request.
type IdentityRequestDTO struct {
	Title          string `json:"title"`
	FirstName      string `json:"firstName"`
	MiddleName     string `json:"middleName"`
	LastName       string `json:"lastName"`
	Address1       string `json:"address1"`
	Address2       string `json:"address2"`
	Address3       string `json:"address3"`
	City           string `json:"city"`
	State          string `json:"state"`
	PostalCode     string `json:"postalCode"`
	Country        string `json:"country"`
	Company        string `json:"company"`
	Email          string `json:"email"`
	Phone          string `json:"phone"`
	SSN            string `json:"ssn"`
	Username       string `json:"username"`
	PassportNumber string `json:"passportNumber"`
	LicenseNumber  string `json:"licenseNumber"`
}

// FieldRequestDTO maps a custom field within a cipher request.
type FieldRequestDTO struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Type     int    `json:"type"`
	LinkedID int    `json:"linkedId,omitempty"`
}
