package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Region represents a Bitwarden cloud region.
type Region string

const (
	// RegionUS is the US cloud region.
	RegionUS Region = "us"
	// RegionEU is the EU cloud region.
	RegionEU Region = "eu"
)

// Environment holds the URLs for all Bitwarden services.
type Environment struct {
	WebVault      string
	API           string
	Identity      string
	Icons         string
	Notifications string
	Events        string
	SCIM          string
	Send          string
}

// NewCloud returns the Environment for the given cloud region.
func NewCloud(region Region) (Environment, error) {
	switch region {
	case RegionUS:
		return Environment{
			WebVault:      "https://vault.bitwarden.com",
			API:           "https://api.bitwarden.com",
			Identity:      "https://identity.bitwarden.com",
			Icons:         "https://icons.bitwarden.net",
			Notifications: "https://notifications.bitwarden.com",
			Events:        "https://events.bitwarden.com",
			SCIM:          "https://scim.bitwarden.com/v2",
			Send:          "https://send.bitwarden.com/#",
		}, nil
	case RegionEU:
		return Environment{
			WebVault:      "https://vault.bitwarden.eu",
			API:           "https://api.bitwarden.eu",
			Identity:      "https://identity.bitwarden.eu",
			Icons:         "https://icons.bitwarden.eu",
			Notifications: "https://notifications.bitwarden.eu",
			Events:        "https://events.bitwarden.eu",
			SCIM:          "https://scim.bitwarden.eu/v2",
			Send:          "https://vault.bitwarden.eu/#/send/",
		}, nil
	default:
		return Environment{}, fmt.Errorf("unknown cloud region: %q", region)
	}
}

// NewSelfHosted returns an Environment derived from a self-hosted base URL.
func NewSelfHosted(base string) (Environment, error) {
	base = strings.TrimSpace(base)

	u, err := url.Parse(base)
	if err != nil {
		return Environment{}, errors.New("self-hosted URL is not parseable")
	}

	if !u.IsAbs() {
		return Environment{}, errors.New("self-hosted URL must be absolute")
	}

	if u.Scheme != "https" {
		return Environment{}, errors.New("self-hosted URL must use https scheme")
	}

	if u.User != nil {
		return Environment{}, errors.New("self-hosted URL must not contain userinfo")
	}

	if u.RawQuery != "" {
		return Environment{}, errors.New("self-hosted URL must not contain a query string")
	}

	if u.Fragment != "" {
		return Environment{}, errors.New("self-hosted URL must not contain a fragment")
	}

	if u.Host == "" {
		return Environment{}, errors.New("self-hosted URL must have a host")
	}

	// Strip all trailing slashes from path.
	u.Path = strings.TrimRight(u.Path, "/")

	// Rebuild to get the normalized base URL.
	baseURL := u.Scheme + "://" + u.Host + u.Path

	return Environment{
		WebVault:      baseURL,
		API:           baseURL + "/api",
		Identity:      baseURL + "/identity",
		Icons:         baseURL + "/icons",
		Notifications: baseURL + "/notifications",
		Events:        baseURL + "/events",
		SCIM:          baseURL + "/scim/v2",
		Send:          baseURL + "/#/send/",
	}, nil
}
