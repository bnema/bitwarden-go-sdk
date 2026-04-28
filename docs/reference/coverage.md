# Coverage Matrix

| Area | Feature | Status | V1 | Evidence | Notes |
| --- | --- | --- | --- | --- | --- |
| Scope | Personal-account SDK baseline | In V1 | Yes | Approved design spec | V1 focuses on free/paid personal account usage only. |
| Environment | US cloud URLs | Mapped | Yes | `default-environment.service.ts:85-99`; `default-environment.service.spec.ts:74-133` | Exact cloud service URLs captured in `docs/reference/environments.md`. |
| Environment | EU cloud URLs | Mapped | Yes | `default-environment.service.ts:100-114`; `default-environment.service.spec.ts:74-133` | Exact cloud service URLs captured in `docs/reference/environments.md`. |
| Environment | Official self-hosted URL derivation | Mapped | Yes | `default-environment.service.ts:215-260,320-330,384-425,442-451`; `default-environment.service.spec.ts:182-215,288-338` | SDK validates direct inputs more strictly while preserving official derivation behavior. |
| Auth | Prelogin by email | Mapped | Yes | `password-prelogin-api.service.ts:9-24`; prelogin request/response DTOs | Endpoint, request body, normalization, and KDF response mapped. |
| Auth | Email + master password login | Mapped | Yes | `password-token.request.ts:6-30`; `identity-token.response.ts:13-101`; login strategy files | Identity token form fields and success response mapped; crypto details mapped in crypto docs. |
| Auth | Classic 2FA | Mapped | Yes | `identity-two-factor.response.ts:5-23`; `two-factor-provider-type.ts:1-9`; login strategy files | Challenge detection, provider IDs, and retry fields mapped; advanced WebAuthn/passkeys remain deferred. |
| Auth | Refresh token | Mapped | Yes | `api.service.ts:1445-1529`; token request/response DTOs | Refresh form fields, invalid-grant behavior, and concurrency implication mapped. |
| Auth | SSO | Deferred | No | Client auth services | Document only. |
| Auth | Login with device | Deferred | No | Client auth services | Document only. |
| Auth | Advanced WebAuthn/passkey login | Deferred | No | Client auth services | Document only. |
| Crypto | KDF | Mapped | Yes | clients KDF config; sdk-internal `kdf.rs:32-119,180-259` | PBKDF2 and Argon2id behavior plus official SDK vectors captured. |
| Crypto | EncString | Mapped | Yes | clients encryption type/EncString model; sdk-internal `symmetric.rs:64-190,220-230` | Symmetric text and buffer formats mapped. |
| Crypto | User key unwrap | Mapped | Yes | clients master password service; sdk-internal `master_key.rs:55-75,129-164,191-337` | Auth hash and user-key unwrap behavior plus official vectors captured. |
| Vault | Sync | Mapped | Yes | `api.service.ts:786-794`; `sync.response.ts:12-64`; `default-sync.service.ts:145-231` | Full sync, exclude-domains option, and response fields mapped. |
| Vault | Ciphers | Mapped | Yes | `api.service.ts:384-460,491-539`; cipher request/response models; cipher service delete semantics | Personal get/create/update/trash/restore/permanent-delete and DTO fields mapped. |
| Vault | Folders | Mapped | Yes | `folder-api.service.ts:16-59`; folder request/response models | Personal folder CRUD and delete-all source mapping captured. |
| Vault | Attachments | Mapped | Yes | `api.service.ts:542-634`; attachment request/response models; file upload services | Metadata, direct/Azure upload, renew, delete, and rollback behavior mapped. |
| Account | Profile | Mapped | Yes | `api.service.ts:270-303`; `profile.response.ts:11-78` | Profile fields and premium flags mapped. |
| Account | Subscription | Mapped | Yes | `api.service.ts:270-303`; `subscription.response.ts:7-104`; billing profile state service | Subscription fields and premium capability detection mapped. |
| Enterprise | Org/admin/enterprise | Deferred | No | Bitwarden license/common code | V2 or later. |
| Compatibility | Vaultwarden | Out of scope | No | none | V1 excludes Vaultwarden. |
