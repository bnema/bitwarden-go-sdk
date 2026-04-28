package bitwarden

// Region identifies a Bitwarden service region.
type Region string

const (
	// RegionUS identifies the US region.
	RegionUS Region = "us"
	// RegionEU identifies the EU region.
	RegionEU Region = "eu"
)

// LoginOptions is the public login input shape for the client facade.
// Password is a plain string in the scaffold so callers can compile against the
// intended API. The auth implementation plan must revisit this with Go 1.26
// secret-memory handling before real login behavior is added.
type LoginOptions struct {
	Email    string
	Password string
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
