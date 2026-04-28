# Account API

## v0.1.0 status

Status: `Mapped`

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/services/api.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: account profile/subscription/revision methods
- Lines: `270-303`
- Role: official account endpoint contracts.

- Source: `/home/brice/dev/clone/clients/libs/common/src/models/response/profile.response.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `ProfileResponse`
- Lines: `11-78`
- Role: official profile response DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/billing/models/response/subscription.response.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `SubscriptionResponse`
- Lines: `7-104`
- Role: official subscription response DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/billing/services/account/billing-account-profile-state.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `hasPremiumFromAnySource$`
- Lines: `35-45`
- Role: premium detection logic.

## Endpoints

| Operation | Method/path | Notes |
| --- | --- | --- |
| Profile | `GET /accounts/profile` | Returns `ProfileResponse`. |
| Update profile | `PUT /accounts/profile` | Out of v0.1.0 unless explicitly needed. |
| Subscription | `GET /accounts/subscription` | Returns `SubscriptionResponse`. |
| Revision date | `GET /accounts/revision-date` | Used by sync freshness check. |

## Profile fields

Important personal-account fields include `Id`, `Name`, `Email`, `EmailVerified`, `Premium`, `PremiumFromOrganization`, `Culture`, `TwoFactorEnabled`, `Key`, `PrivateKey`, `AccountKeys`, `SecurityStamp`, `ForcePasswordReset`, `UsesKeyConnector`, and `VerifyDevices`.

## Subscription fields

`SubscriptionResponse` includes storage fields (`StorageName`, `StorageGb`, `MaxStorageGb`), license/expiration fields, and nullable nested `Subscription`, `UpcomingInvoice`, and `CustomerDiscount` fields.

## Premium detection

Official client state treats a user as premium if either personal premium or premium-from-organization is true. v0.1.0 excludes organization/admin features but may still report this capability flag for personal-account UX decisions.

## Fixtures

- `testdata/bitwarden/auth/account_profile.json`
- `testdata/bitwarden/auth/subscription.json`
