# Sync API

## v0.1.0 status

Status: `Mapped`

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/services/api.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `ApiService.getSync`
- Lines: `786-794`
- Role: official sync endpoint selection.

- Source: `/home/brice/dev/clone/clients/libs/common/src/platform/sync/sync.response.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `SyncResponse`
- Lines: `12-64`
- Role: official sync response DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/platform/sync/default-sync.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `DefaultSyncService`
- Lines: `145-231`
- Role: full sync orchestration and revision-date freshness behavior.

## Contract

- Full sync: `GET {apiURL}/sync`
- Sync excluding equivalent domains: `GET {apiURL}/sync?excludeDomains=true`
- Account revision date: `GET {apiURL}/accounts/revision-date`

## Response fields

Top-level sync response fields include `Profile`, `Folders`, `Collections`, `Ciphers`, `Domains`, `Policies`, `Sends`, and `UserDecryption`.

v0.1.0 consumes personal-account `Profile`, `Folders`, `Ciphers`, `Domains`, and `UserDecryption` fields. Organization/admin collection behavior remains out of scope except where encrypted DTO fields appear in personal sync payloads.

## SDK implications

- Sync is an authenticated API call.
- The SDK decrypts into an in-memory vault snapshot only after login/unlock.
- `excludeDomains=true` must be supported for caller-controlled equivalent-domain behavior.
- Revision-date optimization may be implemented after correctness; full sync behavior is required for v0.1.0.

## Fixtures

- `testdata/bitwarden/sync/sync_response_personal.json`
- `testdata/bitwarden/sync/revision_date_response.json`
