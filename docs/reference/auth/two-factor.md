# Classic Two-Factor Authentication

## v0.1.0 status

Status: `Mapped`

## Purpose

Handle classic Bitwarden 2FA challenges for personal-account login by returning an explicit challenge result and completing login with the selected provider and code.

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/models/response/identity-two-factor.response.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `IdentityTwoFactorResponse`
- Lines: `5-23`
- Role: 2FA challenge response DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/enums/two-factor-provider-type.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `TwoFactorProviderType`
- Lines: `1-9`
- Role: provider identifiers.

- Source: `/home/brice/dev/clone/clients/libs/common/src/auth/models/request/identity-token/token-two-factor.request.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `TokenTwoFactorRequest`
- Lines: `1-10`
- Role: retry fields for 2FA token requests.

- Source: `/home/brice/dev/clone/clients/libs/auth/src/common/login-strategies/login.strategy.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `LoginStrategy` 2FA handling
- Lines: `184-234`, `244-334`
- Role: challenge detection and retry behavior.

## Challenge detection

A 2FA challenge is detected when the identity token endpoint returns HTTP `400` with `TwoFactorProviders2` present and non-empty. The SDK must not treat this as a terminal authentication failure. It must return a challenge result containing the supported providers and enough safe context for a caller to prompt the user.

## Provider identifiers

| ID | Provider | v0.1.0 support |
| --- | --- | --- |
| `0` | Authenticator TOTP | Supported |
| `1` | Email code | Supported |
| `2` | Duo | Supported when present in challenge mapping |
| `3` | YubiKey OTP | Supported when present in challenge mapping |
| `5` | Remember | Internal/response metadata, not a user-entered challenge method |
| `6` | Organization Duo | Out of personal-account scope unless source mapping later proves it is needed for personal accounts |
| `7` | WebAuthn | Deferred |
| `8` | Recovery code | Deferred for v0.1.0 login flow |

## Retry contract

2FA completion retries `POST {identityURL}/connect/token` with the original password grant fields plus:

| Field | Meaning |
| --- | --- |
| `twoFactorToken` | User-entered code or provider token. |
| `twoFactorProvider` | Numeric provider identifier. |
| `twoFactorRemember` | String `1` or `0`. |

## Challenge response fields

| Field | Meaning |
| --- | --- |
| `TwoFactorProviders` | Legacy provider map. |
| `TwoFactorProviders2` | Provider-id keyed challenge metadata. |
| `MasterPasswordPolicy` | Optional policy metadata. |
| `SsoEmail2faSessionToken` | Optional SSO email 2FA session token. |
| `Email` | Email associated with challenge. |

## Fixtures

- `testdata/bitwarden/auth/token_two_factor_response.json`
- `testdata/bitwarden/auth/token_two_factor_completion_request.form`
