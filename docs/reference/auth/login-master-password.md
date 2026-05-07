# Login With Master Password

## v0.1.0 status

Status: `Mapped`

## Purpose

Authenticate with email and master password after deriving the Bitwarden server authentication hash locally. Public API should expose a stateful login flow, not raw identity DTOs.

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/models/request/identity-token/token.request.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `TokenRequest`
- Lines: `20-53`
- Role: base identity token request fields.

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/models/request/identity-token/password-token.request.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `PasswordTokenRequest`
- Lines: `6-30`
- Role: password grant request fields.

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/models/response/identity-token.response.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `IdentityTokenResponse`
- Lines: `13-101`
- Role: token and account unlock response DTO.

- Source: `/home/brice/dev/clone/clients/libs/auth/src/common/login-strategies/password-login.strategy.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `PasswordLoginStrategy`
- Lines: `58-115`, `173-189`
- Role: prelogin, master-key derivation, auth hash, token request orchestration.

- Source: `/home/brice/dev/clone/clients/libs/auth/src/common/login-strategies/login.strategy.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `LoginStrategy.startLogIn`
- Lines: `118-176`, `184-234`, `244-334`
- Role: token response handling and 2FA branch handling.

## Contract

- Method: `POST`
- URL: `{identityURL}/connect/token`
- Request content type: `application/x-www-form-urlencoded; charset=utf-8`
- Accept: `application/json`

Minimum password grant fields:

| Field | Value |
| --- | --- |
| `grant_type` | `password` |
| `username` | normalized email |
| `password` | server authentication hash derived locally |
| `scope` | `api offline_access` |
| `client_id` | client type identifier |
| `deviceType` | device type identifier, when available |
| `deviceIdentifier` | stable device identifier, when available |
| `deviceName` | display device name, when available |

Optional fields include `newDeviceOtp`, `authRequest`, `twoFactorToken`, `twoFactorProvider`, and `twoFactorRemember` when retrying after a 2FA challenge.

## Success response fields

| Field | Meaning |
| --- | --- |
| `access_token` | OAuth access token. Runtime secret. |
| `refresh_token` | OAuth refresh token. Runtime secret. |
| `token_type` | OAuth token type. |
| `expires_in` | Lifetime in seconds. |
| `PrivateKey` | Encrypted private key material if present. |
| `AccountKeys` | Account key collection if present. |
| `Key` | Encrypted user key. |
| `TwoFactorToken` | Remembered 2FA token if present. |
| `Kdf`, `KdfIterations`, `KdfMemory`, `KdfParallelism` | KDF metadata returned with token response. |
| `ForcePasswordReset`, `ApiUseKeyConnector`, `MasterPasswordPolicy`, `UserDecryptionOptions` | Account/login policy metadata. |

## SDK implications

- `Client.BeginLogin` must orchestrate prelogin, crypto derivation, identity token request, 2FA handling, token storage, and in-memory unlock state.
- Token values are runtime secrets and must never be logged or printed in errors.
- Raw response DTOs stay internal.

## Fixtures

- `testdata/bitwarden/auth/token_password_request.form`
- `testdata/bitwarden/auth/token_success_response.json`
