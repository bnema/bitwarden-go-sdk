# Classic Two-Factor Authentication

## V1 status

Status: `In V1`

## Purpose

Handle classic Bitwarden 2FA challenges such as authenticator code and email code where available for personal accounts.

## Evidence to map

- Client source: `libs/common/src/services/api.service.ts`
- Server source: not mapped yet

## SDK implication

The SDK must return an inspectable `TwoFactorError` so callers can prompt for a code and retry without losing login context.
