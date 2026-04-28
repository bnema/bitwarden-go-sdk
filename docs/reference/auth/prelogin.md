# Prelogin

## v0.1.0 status

Status: `Mapped`

## Purpose

Fetch KDF parameters before master-password authentication. The SDK uses this internally during login and does not expose a raw prelogin endpoint in the public API.

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/password-prelogin/password-prelogin-api.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `PasswordPreloginApiService.postPrelogin`
- Lines: `9-24`
- Role: official client API call.

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/password-prelogin/password-prelogin.request.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `PasswordPreloginRequest`
- Lines: `1-7`
- Role: official request DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/password-prelogin/password-prelogin.response.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `PasswordPreloginResponse`
- Lines: `7-19`
- Role: official response DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/password-prelogin/default-password-prelogin.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `DefaultPasswordPreloginService`
- Lines: `14-36`
- Role: email normalization and response model construction.

## Contract

- Method: `POST`
- URL: `{identityURL}/accounts/prelogin/password`
- Request content type: `application/json; charset=utf-8`
- Accept: `application/json`
- Request body:

```json
{ "email": "user@example.com" }
```

Email is trimmed and lower-cased before request construction.

## Response fields

| Field | Type | Meaning |
| --- | --- | --- |
| `Kdf` | number | KDF identifier: `0` PBKDF2-SHA256, `1` Argon2id. |
| `KdfIterations` | number | PBKDF2 iterations or Argon2id iterations. |
| `KdfMemory` | number, optional | Argon2id memory in MiB. |
| `KdfParallelism` | number, optional | Argon2id parallelism. |

## Fixtures

- `testdata/bitwarden/auth/prelogin_request.json`
- `testdata/bitwarden/auth/prelogin_response_pbkdf2.json`
- `testdata/bitwarden/auth/prelogin_response_argon2id.json`
