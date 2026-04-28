package core

import "github.com/bnema/bitwarden-go-sdk/internal/ports"

// Client wires scaffold dependencies for future SDK orchestration.
type Client struct {
	identity ports.IdentityClient
	api      ports.APIClient
	crypto   ports.CryptoEngine
	logger   ports.Logger
}

// Dependencies groups outbound dependencies used by Client.
type Dependencies struct {
	Identity ports.IdentityClient
	API      ports.APIClient
	Crypto   ports.CryptoEngine
	Logger   ports.Logger
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
