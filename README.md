# bitwarden-go-sdk

This SDK provides an idiomatic, stateful Go client for reading and writing
Bitwarden vaults so it can be reused on different projects

> Status: alpha release, still very much in development. API subject to change without deprecation.

## Scope

- Personal Bitwarden accounts with master-password login.
- Two-factor authentication (authenticator app, email, YubiKey, Duo).
- **Bitwarden cloud regions:** US (`vault.bitwarden.com`) and EU (`vault.bitwarden.eu`).
- **Official self-hosted Bitwarden** (the .NET Server, not Vaultwarden).
- Vault item CRUD: list, search, get, create, update, trash, restore, delete.
- Folder CRUD: list, create, update, delete.
- Attachment upload, download, metadata, and delete.
- Automatic OAuth token refresh (background, race-safe).
- Hexagonal architecture with Mockery-generated mocks for testability.


## Non-goals (yet)

- **Vaultwarden** — use the [bitwarden/server](https://github.com/bitwarden/server)
  official self-hosted deployment.
- **Organization / admin / enterprise** features (collections, policies, user
  management, etc.).
- **SSO (Single Sign-On)** login flows.
- **Login-with-device** authentication.
- **WebAuthn / passkeys** as a two-factor provider or primary auth.
- **Live tests against Bitwarden by default** — tests use mocked interfaces.
- **SDK-managed disk persistence** — session tokens are kept in memory only;
  callers that need persistence must wrap the SDK at the application boundary.

---

## Quick start snippets

### NewClient

```go
package main

import (
    "context"
    "log"

    "github.com/bnema/bitwarden-go-sdk/bitwarden"
)

func main() {
    ctx := context.Background()

    // US cloud (default):
    client, err := bitwarden.NewClient()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // EU cloud:
    clientEU, err := bitwarden.NewClient(bitwarden.WithRegion(bitwarden.RegionEU))
    if err != nil {
        log.Fatal(err)
    }
    defer clientEU.Close()

    // Self-hosted (official Bitwarden, not Vaultwarden):
    clientSH, err := bitwarden.NewClient(
        bitwarden.WithServerURL("https://bitwarden.example.com"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer clientSH.Close()

    _ = ctx
    _ = client
    _ = clientEU
    _ = clientSH
}
```

### BeginLogin / CompleteLogin

```go
result, err := client.BeginLogin(ctx, bitwarden.LoginOptions{
    Email:    "alice@example.com",
    Password: "REPLACE_ME",
})
if err != nil {
    log.Fatal(err)
}

if result.Challenge != nil {
    // Two-factor required. Choose a provider and complete login.
    log.Println("providers:", result.Challenge.Providers())
    result, err = client.CompleteLogin(ctx, bitwarden.CompleteLoginOptions{
        Challenge: result.Challenge,
        Provider:  bitwarden.TwoFactorProviderAuthenticator,
        Code:      "REPLACE_ME",
        Remember:  true,
    })
    if err != nil {
        log.Fatal(err)
    }
}

log.Println("logged in as account:", result.AccountID)
```

### Sync / Search

```go
// Sync vault — fetches and decrypts cipher data from the server.
if err := client.Sync(ctx); err != nil {
    log.Fatal(err)
}

// List all items.
items, err := client.Vault().List(ctx)
if err != nil {
    log.Fatal(err)
}

// Search by keyword (case-insensitive, safe fields only).
results, err := client.Vault().Search(ctx, "example")
if err != nil {
    log.Fatal(err)
}

for _, item := range results {
    log.Printf("  %s: %s", item.ID, item.Name)
}
```

### Attachments

```go
att := client.Attachments()

// Upload from a file.
info, err := att.Upload(ctx, bitwarden.AttachmentUploadOptions{
    ItemID:   "REPLACE_ME",
    FileName: "receipt.pdf",
    Size:     42,
    Reader:   someReader,
})
if err != nil {
    log.Fatal(err)
}

// Download to a writer.
var buf bytes.Buffer
if err := att.Download(ctx, info.CipherID, info.ID, &buf); err != nil {
    log.Fatal(err)
}

// List attachments — use Vault.Get then inspect attachment URLs.
meta, err := att.Metadata(ctx, info.CipherID, info.ID)
if err != nil {
    log.Fatal(err)
}
log.Println("attachment:", meta.FileName)
```

> **Important:** All code samples above use `REPLACE_ME` placeholders. Replace
> them with real values before running. Never commit real secrets to version
> control.

---

## Secret handling

Sensitive data (passwords, TOTP secrets, card numbers, identity numbers) is
wrapped in `*Secret` to prevent accidental exposure:

- `String()` and `GoString()` always return `[REDACTED]`.
- `MarshalJSON()` returns an error — secrets cannot be serialised to JSON.
- Call `Reveal()` to obtain a `*RevealedSecret` for transient access.
- Call `Close()` on both `Secret` and `RevealedSecret` to zeroise the buffer.
- Build with `GOEXPERIMENT=runtimesecret` to enable Go's experimental
  `runtime/secret` support for enhanced stack/register erasure while copying
  and clearing secret bytes. Without that flag, the SDK falls back to standard
  Go memory handling plus explicit buffer zeroisation on `Close()`; this keeps
  API behavior identical but provides weaker runtime erasure guarantees.

```go
password := item.Password // *Secret
revealed, err := password.Reveal()
if err != nil {
    // secret already closed
}
defer revealed.Close()
plaintext := revealed.String() // use it, then zeroised via Close()
```

Token storage is a **sensitive boundary**. The SDK's internal in-memory store
zeroises replaced and deleted tokens. The SDK does **not** persist tokens to
disk — callers that need persistence should handle it outside the SDK boundary
with their own secure storage policy.

The SDK never logs master passwords, OAuth tokens, user keys, plaintext vault
fields, sensitive headers, or decrypted payloads. No HTTP request or response
body dumps are emitted.

---

## Self-hosted URL rules

When using `WithServerURL`, the base URL must satisfy these rules:

| Rule | Reason |
|------|--------|
| `https` scheme required | All Bitwarden traffic must be encrypted. |
| No userinfo (`user:pass@`) | Credentials must not be embedded in URLs. |
| No query string (`?key=val`) | Not a valid server base URL. |
| No fragment (`#section`) | Not a valid server base URL. |
| Must be absolute (has host) | A relative path is meaningless. |
| Trailing slashes are stripped | Normalised internally. |

Valid examples:

```
https://bitwarden.example.com
https://vault.mycompany.com:8443
https://192.168.1.50
```

Invalid:

```
http://bitwarden.example.com       (not https)
https://user:pass@example.com      (contains userinfo)
https://example.com?region=eu      (has query)
https://example.com#section        (has fragment)
bitwarden.example.com              (not absolute)
```

---

## Tests and checks

Run the full check suite (fmt, build, test, lint):

```bash
make check
```

Run tests for the SDK package only:

```bash
go test ./bitwarden/...
```

Live tests against a real Bitwarden instance are **not enabled by default**.
All tests use mocked interfaces. To run live tests, you must supply credentials
via environment variables or a test configuration — see `testdata/` for fixture
examples.

---

## Project layout

- `bitwarden/` — public idiomatic client API (`Client`, `Vault`, `Folders`,
  `Attachments`, `Secret`, `Error`, etc.).
- `internal/core/` — use-case orchestration (auth, vault, folders, attachments,
  session refresh).
- `internal/ports/` — mockable outbound port interfaces (identity, API, crypto,
  token store).
- `internal/adapters/` — concrete HTTP, crypto, memory, and config adapters.
- `docs/reference/` — source-backed Bitwarden reference documentation.
- `testdata/bitwarden/` — sanitised fixtures derived from official source
  mapping.

---

## License

MIT — see `LICENSE`.
