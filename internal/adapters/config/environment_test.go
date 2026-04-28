package config

import (
	"testing"
)

// -------- test helpers --------

func wantEnvironment(webVault, api, identity, icons, notifications, events, scim, send string) Environment {
	return Environment{
		WebVault:      webVault,
		API:           api,
		Identity:      identity,
		Icons:         icons,
		Notifications: notifications,
		Events:        events,
		SCIM:          scim,
		Send:          send,
	}
}

func assertEnvironmentEqual(t *testing.T, got, want Environment) {
	t.Helper()
	if got.WebVault != want.WebVault {
		t.Errorf("WebVault: got %q, want %q", got.WebVault, want.WebVault)
	}
	if got.API != want.API {
		t.Errorf("API: got %q, want %q", got.API, want.API)
	}
	if got.Identity != want.Identity {
		t.Errorf("Identity: got %q, want %q", got.Identity, want.Identity)
	}
	if got.Icons != want.Icons {
		t.Errorf("Icons: got %q, want %q", got.Icons, want.Icons)
	}
	if got.Notifications != want.Notifications {
		t.Errorf("Notifications: got %q, want %q", got.Notifications, want.Notifications)
	}
	if got.Events != want.Events {
		t.Errorf("Events: got %q, want %q", got.Events, want.Events)
	}
	if got.SCIM != want.SCIM {
		t.Errorf("SCIM: got %q, want %q", got.SCIM, want.SCIM)
	}
	if got.Send != want.Send {
		t.Errorf("Send: got %q, want %q", got.Send, want.Send)
	}
}

// -------- table-driven tests --------

func TestEnvironment_NewCloud_US(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		region Region
		want   Environment
	}{
		{
			name:   "us cloud returns expected URLs",
			region: RegionUS,
			want: wantEnvironment(
				"https://vault.bitwarden.com",
				"https://api.bitwarden.com",
				"https://identity.bitwarden.com",
				"https://icons.bitwarden.net",
				"https://notifications.bitwarden.com",
				"https://events.bitwarden.com",
				"https://scim.bitwarden.com/v2",
				"https://send.bitwarden.com/#",
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCloud(tt.region)
			if err != nil {
				t.Fatalf("NewCloud(%q) returned error: %v", tt.region, err)
			}
			assertEnvironmentEqual(t, got, tt.want)
		})
	}
}

func TestEnvironment_NewCloud_EU(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		region Region
		want   Environment
	}{
		{
			name:   "eu cloud returns expected URLs",
			region: RegionEU,
			want: wantEnvironment(
				"https://vault.bitwarden.eu",
				"https://api.bitwarden.eu",
				"https://identity.bitwarden.eu",
				"https://icons.bitwarden.eu",
				"https://notifications.bitwarden.eu",
				"https://events.bitwarden.eu",
				"https://scim.bitwarden.eu/v2",
				"https://vault.bitwarden.eu/#/send/",
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCloud(tt.region)
			if err != nil {
				t.Fatalf("NewCloud(%q) returned error: %v", tt.region, err)
			}
			assertEnvironmentEqual(t, got, tt.want)
		})
	}
}

func TestEnvironment_NewSelfHosted_RootBase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		base string
		want Environment
	}{
		{
			name: "root base strips trailing slash and derives URLs",
			base: "https://bitwarden.example.com/",
			want: wantEnvironment(
				"https://bitwarden.example.com",
				"https://bitwarden.example.com/api",
				"https://bitwarden.example.com/identity",
				"https://bitwarden.example.com/icons",
				"https://bitwarden.example.com/notifications",
				"https://bitwarden.example.com/events",
				"https://bitwarden.example.com/scim/v2",
				"https://bitwarden.example.com/#/send/",
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSelfHosted(tt.base)
			if err != nil {
				t.Fatalf("NewSelfHosted(%q) returned error: %v", tt.base, err)
			}
			assertEnvironmentEqual(t, got, tt.want)
		})
	}
}

func TestEnvironment_NewSelfHosted_SubpathBase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		base string
		want Environment
	}{
		{
			name: "subpath base preserves path and derives URLs under it",
			base: "https://example.com/bitwarden/",
			want: wantEnvironment(
				"https://example.com/bitwarden",
				"https://example.com/bitwarden/api",
				"https://example.com/bitwarden/identity",
				"https://example.com/bitwarden/icons",
				"https://example.com/bitwarden/notifications",
				"https://example.com/bitwarden/events",
				"https://example.com/bitwarden/scim/v2",
				"https://example.com/bitwarden/#/send/",
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSelfHosted(tt.base)
			if err != nil {
				t.Fatalf("NewSelfHosted(%q) returned error: %v", tt.base, err)
			}
			assertEnvironmentEqual(t, got, tt.want)
		})
	}
}

func TestEnvironment_NewSelfHosted_MultipleTrailingSlashes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		base string
		want Environment
	}{
		{
			name: "multiple trailing slashes are all stripped",
			base: "https://example.com/bitwarden//",
			want: wantEnvironment(
				"https://example.com/bitwarden",
				"https://example.com/bitwarden/api",
				"https://example.com/bitwarden/identity",
				"https://example.com/bitwarden/icons",
				"https://example.com/bitwarden/notifications",
				"https://example.com/bitwarden/events",
				"https://example.com/bitwarden/scim/v2",
				"https://example.com/bitwarden/#/send/",
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSelfHosted(tt.base)
			if err != nil {
				t.Fatalf("NewSelfHosted(%q) returned error: %v", tt.base, err)
			}
			assertEnvironmentEqual(t, got, tt.want)
		})
	}
}

func TestEnvironment_NewSelfHosted_RejectsInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		base string
	}{
		{name: "http scheme", base: "http://bitwarden.example.com"},
		{name: "userinfo", base: "https://user@example.com"},
		{name: "query string", base: "https://bitwarden.example.com?region=us"},
		{name: "fragment", base: "https://bitwarden.example.com/#/vault"},
		{name: "relative URL", base: "bitwarden.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSelfHosted(tt.base)
			if err == nil {
				t.Errorf("NewSelfHosted(%q) expected error, got nil", tt.base)
			}
		})
	}
}
