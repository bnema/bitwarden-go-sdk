package core

import "github.com/bnema/bitwarden-go-sdk/internal/ports/out"

type Client struct {
	identity out.IdentityClient
	api      out.APIClient
	crypto   out.CryptoEngine
	logger   out.Logger
}

type Dependencies struct {
	Identity out.IdentityClient
	API      out.APIClient
	Crypto   out.CryptoEngine
	Logger   out.Logger
}

func NewClient(deps Dependencies) *Client {
	return &Client{
		identity: deps.Identity,
		api:      deps.API,
		crypto:   deps.Crypto,
		logger:   deps.Logger,
	}
}
