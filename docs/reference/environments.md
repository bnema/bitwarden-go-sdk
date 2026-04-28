# Environments and Regions

## V1 status

Implementation status: `In V1`
Mapping status: `Unknown` until source line citations are added.

## Scope

- Bitwarden US cloud.
- Bitwarden EU cloud.
- Official self-hosted Bitwarden.

## Preliminary official client mapping to verify

US cloud:

- API: `https://api.bitwarden.com`
- Identity: `https://identity.bitwarden.com`
- Icons: `https://icons.bitwarden.net`
- Notifications: `https://notifications.bitwarden.com`
- Events: `https://events.bitwarden.com`
- Web vault: `https://vault.bitwarden.com`

EU cloud:

- API: `https://api.bitwarden.eu`
- Identity: `https://identity.bitwarden.eu`
- Icons: `https://icons.bitwarden.eu`
- Notifications: `https://notifications.bitwarden.eu`
- Events: `https://events.bitwarden.eu`
- Web vault: `https://vault.bitwarden.eu`

Self-hosted official Bitwarden derives service URLs from a base URL:

- API: `{base}/api`
- Identity: `{base}/identity`
- Icons: `{base}/icons`
- Notifications: `{base}/notifications`
- Events: `{base}/events`
- Web vault: `{base}`

## Evidence to verify

- Client source: `libs/common/src/platform/services/default-environment.service.ts`
- Server source: not mapped yet
