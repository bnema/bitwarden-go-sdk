# Token Refresh

## v0.1.0 status

Status: `Mapped`

## Purpose

Refresh access tokens without forcing unnecessary full login flows and without causing duplicate refresh storms when concurrent SDK calls notice an expired token.

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/services/api.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `ApiService.refreshIdentityToken`, identity request helpers
- Lines: `1445-1529`, `1575-1752`, `1786-1796`
- Role: refresh request, response handling, headers, and invalid-grant behavior.

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/models/request/identity-token/token.request.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `TokenRequest`
- Lines: `20-53`
- Role: base token request fields.

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/models/response/identity-token.response.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `IdentityTokenResponse`
- Lines: `13-101`
- Role: token response DTO.

## Contract

- Method: `POST`
- URL: `{identityURL}/connect/token`
- Request content type: `application/x-www-form-urlencoded; charset=utf-8`
- Accept: `application/json`

Refresh fields:

| Field | Value |
| --- | --- |
| `grant_type` | `refresh_token` |
| `client_id` | client ID from current token/account context |
| `refresh_token` | stored refresh token runtime secret |

Success returns the same token response shape as password login, including new `access_token` and `refresh_token` when present.

## Invalid grant behavior

If refresh returns HTTP `400` with JSON field `error` equal to `invalid_grant`, official clients invoke logout/session-expired handling. The Go SDK must map this to a safe public authentication/session-expired error, clear token state according to the TokenStore contract, and must not log token values.

## Concurrency

Official clients coalesce refresh work per user with a shared in-flight promise and delete it in `finally`. The Go SDK must provide equivalent per-account refresh coordination so concurrent callers share one remote refresh request.

## Fixtures

- `testdata/bitwarden/auth/token_refresh_request.form`
- `testdata/bitwarden/auth/token_refresh_response.json`
- `testdata/bitwarden/auth/token_invalid_grant_response.json`
