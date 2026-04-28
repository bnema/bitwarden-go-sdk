# Coverage Matrix

| Area | Feature | Status | V1 | Evidence | Notes |
| --- | --- | --- | --- | --- | --- |
| Environment | US cloud URLs | Unknown | Yes | `default-environment.service.ts` | Preliminary design value exists; verify with source line citations before implementation. |
| Environment | EU cloud URLs | Unknown | Yes | `default-environment.service.ts` | Preliminary design value exists; verify with source line citations before implementation. |
| Environment | Official self-hosted URL derivation | Unknown | Yes | `default-environment.service.ts` | Preliminary design value exists; verify with source line citations before implementation. |
| Auth | Prelogin by email | Unknown | Yes | `password-prelogin-api.service.ts` | Needs endpoint and DTO mapping. |
| Auth | Email + master password login | Unknown | Yes | `api.service.ts`, master password service | Needs identity token and crypto mapping. |
| Auth | Classic 2FA | Unknown | Yes | `api.service.ts` | Needs providers and retry flow mapping. |
| Auth | Refresh token | Unknown | Yes | `api.service.ts` | Needs concurrency and error behavior. |
| Auth | SSO | Deferred | No | Client auth services | Document only. |
| Auth | Login with device | Deferred | No | Client auth services | Document only. |
| Auth | Advanced WebAuthn/passkey login | Deferred | No | Client auth services | Document only. |
| Crypto | KDF | Unknown | Yes | key-management files | Needs PBKDF2 and Argon2id mapping. |
| Crypto | EncString | Unknown | Yes | crypto models | Needs format mapping. |
| Crypto | User key unwrap | Unknown | Yes | master password service | Needs exact inputs and errors. |
| Vault | Sync | Unknown | Yes | `api.service.ts` | Needs `/sync` response mapping. |
| Vault | Ciphers | Unknown | Yes | `api.service.ts`, cipher service | Needs CRUD and decrypt/encrypt mapping. |
| Vault | Folders | Unknown | Yes | folder API service | Needs CRUD and decrypt/encrypt mapping. |
| Vault | Attachments | Unknown | Yes | file upload service | Needs upload/download/key mapping. |
| Account | Profile | Unknown | Yes | `api.service.ts` | Needed for account identification. |
| Account | Subscription | Unknown | Yes | `api.service.ts` | Needed for free/premium detection. |
| Enterprise | Org/admin/enterprise | Deferred | No | Bitwarden license/common code | V2 or later. |
| Compatibility | Vaultwarden | Out of scope | No | none | V1 excludes Vaultwarden. |
