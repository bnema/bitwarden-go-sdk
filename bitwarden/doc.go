// Package bitwarden provides the public SDK facade for the bitwarden-go-sdk.
//
// The package exposes a stateful Client that supports master-password login
// (with two-factor authentication), vault item and folder CRUD, attachment
// operations, and automatic OAuth token refresh. Sensitive plaintext is
// wrapped in the Secret type, which redacts String/GoString/MarshalJSON
// and zeroises on Close.
//
// Supported targets:
//   - Bitwarden cloud (US and EU regions)
//   - Official self-hosted Bitwarden (.NET Server)
//
// Non-goals for the current SDK:
//   - Vaultwarden, SSO, login-with-device, WebAuthn/passkeys
//   - Organization, admin, or enterprise features
//   - SDK-managed disk persistence
//   - Live tests by default (all tests use mocked interfaces)
//
// Secret-memory handling
//
//   - Secret / RevealedSecret: redacted by default, zeroised on Close.
//   - Token storage is a sensitive boundary; the internal default store lives
//     in memory and zeroises replaced/deleted tokens.
//   - The SDK never logs master passwords, OAuth tokens, user keys, plaintext
//     vault fields, sensitive headers, or decrypted payloads.
//   - No HTTP request or response body dumps are emitted.
//
// Self-hosted URL rules (WithServerURL)
//
//   - https scheme required, no userinfo, no query, no fragment, absolute,
//     trailing slashes stripped.
//
// For usage examples see the project README.
package bitwarden
