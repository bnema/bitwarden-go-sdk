package core

import "github.com/bnema/bitwarden-go-sdk/internal/ports/out"

// Client wires scaffold dependencies for future SDK orchestration.
type Client struct {
	identity out.IdentityClient
	api      out.APIClient
	crypto   out.CryptoEngine
	logger   out.Logger
}

// Dependencies groups outbound dependencies used by Client.
type Dependencies struct {
	Identity out.IdentityClient
	API      out.APIClient
	Crypto   out.CryptoEngine
	Logger   out.Logger
}

// NewClient constructs an internal scaffold client.
func NewClient(deps Dependencies) *Client {
	return &Client{
		identity: deps.Identity,
		api:      deps.API,
		crypto:   deps.Crypto,
		logger:   deps.Logger,
	}
}
