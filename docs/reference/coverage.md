# Coverage Matrix

> **v0.1.0 note:** Implementation is backed by local testkit mocks and contract tests; live-server integration tests are not enabled by default.

| Area | Feature | Status | V1 | Evidence | Notes |
| --- | --- | --- | --- | --- | --- |
| Scope | Personal-account SDK baseline | Mapped | Yes | Approved design spec; `bitwarden/client.go`, `bitwarden/auth.go`, `bitwarden/vault_*_test.go` | V1 focuses on free/paid personal account usage only. Implemented with local testkit. Live tests not default. |
| Environment | US cloud URLs | Mapped | Yes | `internal/adapters/config/environment.go` | Exact cloud service URLs captured in `docs/reference/environments.md`. |
| Environment | EU cloud URLs | Mapped | Yes | `internal/adapters/config/environment.go` | Exact cloud service URLs captured in `docs/reference/environments.md`. |
| Environment | Official self-hosted URL derivation | Mapped | Yes | `internal/adapters/config/environment.go:40-75` | SDK validates direct inputs more strictly while preserving official derivation behavior. |
| Auth | Prelogin by email | Mapped | Yes | `internal/adapters/http/identity_client.go`; `bitwarden/auth.go` | Endpoint, request body, normalization, and KDF response implemented. |
| Auth | Email + master password login | Mapped | Yes | `bitwarden/auth.go:52-96`; `bitwarden/client.go:149-161` | Identity token form fields and success response implemented; crypto details in `internal/adapters/crypto/`. |
| Auth | Classic 2FA | Mapped | Yes | `bitwarden/auth.go:19-47`; `bitwarden/errors.go:161-180` | Challenge detection, provider IDs, and retry fields implemented; advanced WebAuthn/passkeys remain deferred. |
| Auth | Refresh token | Mapped | Yes | `bitwarden/client.go:194-209`; `internal/adapters/http/identity_client.go` | Refresh form fields, invalid-grant behavior, and concurrency implication implemented via token store. |
| Auth | SSO | Deferred | No | Client auth services | Document only. |
| Auth | Login with device | Deferred | No | Client auth services | Document only. |
| Auth | Advanced WebAuthn/passkey login | Deferred | No | Client auth services | Document only. |
| Crypto | KDF | Mapped | Yes | `internal/adapters/crypto/engine.go`; `internal/adapters/crypto/helpers.go` | PBKDF2 and Argon2id behavior plus official SDK vectors implemented. |
| Crypto | EncString | Mapped | Yes | `internal/adapters/crypto/enc_string.go`; `internal/adapters/crypto/enc_string_test.go` | Symmetric text and buffer formats implemented. |
| Crypto | User key unwrap | Mapped | Yes | `internal/adapters/crypto/engine.go`; `internal/adapters/crypto/helpers.go` | Auth hash and user-key unwrap behavior plus official vectors implemented. |
| Vault | Sync | Mapped | Yes | `bitwarden/client.go:163-173`; `internal/adapters/http/vault_client.go` | Full sync, exclude-domains option, and response fields implemented. |
| Vault | Ciphers | Mapped | Yes | `bitwarden/client.go:348-662`; `bitwarden/vault_read_test.go`, `vault_write_test.go` | Personal get/create/update/trash/restore/permanent-delete implemented. |
| Vault | Folders | Mapped | Yes | `bitwarden/client.go:666-720`; `bitwarden/folders_test.go` | Personal folder CRUD implemented. |
| Vault | Attachments | Mapped | Yes | `bitwarden/attachments.go`; `bitwarden/attachments_contract_test.go` | Metadata, direct upload, download, and delete implemented. Azure upload remains deferred. |
| Account | Profile | Mapped | Yes | `bitwarden/account.go:62-78` | Profile fields and premium flags implemented. |
| Account | Subscription | Mapped | Yes | `bitwarden/account.go:80-96` | Subscription fields and premium capability detection implemented. |
| Enterprise | Org/admin/enterprise | Deferred | No | Bitwarden license/common code | V2 or later. |
| Compatibility | Vaultwarden | Out of scope | No | none | V1 excludes Vaultwarden. |
