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

// Item is the public vault item shape.
type Item struct {
	ID       ItemID
	Name     string
	Username string
	URI      string
	Type     ItemType
}

// ItemType identifies the kind of vault item.
type ItemType string

const (
	// ItemTypeLogin identifies a login item.
	ItemTypeLogin ItemType = "login"
	// ItemTypeSecureNote identifies a secure note item.
	ItemTypeSecureNote ItemType = "secure_note"
)
