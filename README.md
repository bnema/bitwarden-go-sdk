# bitwarden-go-sdk

Local-first Go SDK for Bitwarden and official self-hosted Bitwarden instances.

> Status: early repository scaffold. The initial milestone is source-backed reference documentation and architecture validation before real SDK behavior is implemented.

## Goals

- Provide an idiomatic, stateful Go SDK for Bitwarden.
- Keep raw Bitwarden endpoint DTOs internal.
- Handle Bitwarden client-side cryptography in Go.
- Optimize for low-latency desktop usage.
- Use hexagonal internals with Mockery-generated mocks.

## Non-goals for the first implementation milestone

- No GTK4 layer-shell UI in this repository.
- No Vaultwarden support.
- No org/admin/enterprise support.
- No SSO, login-with-device, or advanced WebAuthn/passkey login.
- No HTTP body dumps.
- No default live tests against Bitwarden.
- No imposed persistent disk cache.

## Scaffold constraints

- This repository currently contains scaffolding and reference-documentation structure only.
- Do not add real Bitwarden SDK behavior until the source-backed reference docs and a feature-specific implementation plan are approved.
- Do not add HTTP request or response body dumps, even behind debug flags.
- Do not use real secrets, tokens, or plaintext vault data in docs, examples, logs, tests, or fixtures.

## Layout

- `bitwarden/` — public idiomatic client API.
- `internal/core/` — use-case orchestration.
- `internal/ports/out/` — mockable outbound ports.
- `internal/adapters/` — concrete HTTP, crypto, memory, and config adapters.
- `docs/reference/` — source-backed Bitwarden reference documentation.
- `testdata/bitwarden/` — sanitized fixtures derived from official source mapping.

## Development

```bash
make check
```

The repository is local for now. A future `gtk4ls-bitwarden` project can use:

```go
replace github.com/bnema/bitwarden-go-sdk => ../bitwarden-go-sdk
```
