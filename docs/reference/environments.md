# Environments and Regions

## v0.1.0 status

Implementation status: `In v0.1.0`
Mapping status: `Mapped`

## Scope

- Bitwarden US cloud.
- Bitwarden EU cloud.
- Official self-hosted Bitwarden from one base server URL.

The public SDK exposes only region selection or one self-hosted base URL. It does not expose per-service URL overrides in v0.1.0 unless a later source-mapping update proves they are needed for the supported application use case.

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/platform/abstractions/environment.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: `Urls`, `Region`
- Lines: `5-25`
- Role: official Bitwarden client environment model.

- Source: `/home/brice/dev/clone/clients/libs/common/src/platform/services/default-environment.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: `PRODUCTION_REGIONS`, `SelfHostedEnvironment`, `CloudEnvironment`, `formatUrl`
- Lines: `85-114`, `215-260`, `320-330`, `349-357`, `384-425`, `428-467`
- Role: official Bitwarden client environment resolution.

- Source: `/home/brice/dev/clone/clients/libs/common/src/platform/services/default-environment.service.spec.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: environment service tests
- Lines: `74-133`, `182-215`, `288-338`
- Role: official client expected URL behavior.

## US cloud

| Service | URL |
| --- | --- |
| Web vault | `https://vault.bitwarden.com` |
| API | `https://api.bitwarden.com` |
| Identity | `https://identity.bitwarden.com` |
| Icons | `https://icons.bitwarden.net` |
| Notifications | `https://notifications.bitwarden.com` |
| Events | `https://events.bitwarden.com` |
| SCIM base | `https://scim.bitwarden.com` |
| Send | `https://send.bitwarden.com/#` |

## EU cloud

| Service | URL |
| --- | --- |
| Web vault | `https://vault.bitwarden.eu` |
| API | `https://api.bitwarden.eu` |
| Identity | `https://identity.bitwarden.eu` |
| Icons | `https://icons.bitwarden.eu` |
| Notifications | `https://notifications.bitwarden.eu` |
| Events | `https://events.bitwarden.eu` |
| SCIM base | `https://scim.bitwarden.eu/v2` |
| Send | `https://vault.bitwarden.eu/#/send/` |

## Self-hosted derivation

For a self-hosted base URL `{base}`, the official client derives:

| Service | Derived URL |
| --- | --- |
| Web vault | `{base}` |
| API | `{base}/api` |
| Identity | `{base}/identity` |
| Icons | `{base}/icons` |
| Notifications | `{base}/notifications` |
| Events | `{base}/events` |
| SCIM | `{base}/scim/v2` |
| Send | `{base}/#/send/` |

Official client normalization trims whitespace, strips trailing slashes, and prepends `https://` when the user does not provide `http://` or `https://`. The Angular self-hosted configuration dialog rejects non-HTTPS URLs in non-development builds, but the lower-level environment service itself accepts `http://`.

## v0.1.0 SDK validation policy

The Go SDK is stricter than the lower-level TypeScript environment service because SDK inputs are accepted directly from applications:

- require an absolute `https://` URL for self-hosted server URLs;
- reject URL userinfo;
- reject query strings;
- reject fragments;
- strip trailing slashes before deriving service URLs;
- preserve path segments and derive services under the path.

Examples:

- `https://bitwarden.example.com/` derives `https://bitwarden.example.com/api` and `https://bitwarden.example.com/identity`.
- `https://example.com/bitwarden/` derives `https://example.com/bitwarden/api` and `https://example.com/bitwarden/identity`.

## Deferred or excluded

- Per-service public URL overrides are not part of v0.1.0.
- Vaultwarden compatibility is out of scope.
- Server-side deployment constraints for arbitrary subpath hosting are not mapped; the official client preserves subpaths when deriving service URLs.
