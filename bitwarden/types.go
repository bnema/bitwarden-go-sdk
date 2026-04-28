package bitwarden

type Region string

const (
	RegionUS Region = "us"
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

type ItemID string

type Item struct {
	ID       ItemID
	Name     string
	Username string
	URI      string
	Type     ItemType
}

type ItemType string

const (
	ItemTypeLogin      ItemType = "login"
	ItemTypeSecureNote ItemType = "secure_note"
)
