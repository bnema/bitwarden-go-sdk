# Prelogin

## V1 status

Status: `In V1`

## Purpose

Fetch KDF and account preparation data before master-password authentication.

## Evidence to map

- Client source: `libs/common/src/auth/password-prelogin/password-prelogin-api.service.ts`
- Server source: not mapped yet

## SDK implication

The SDK must expose this through `Client.Login` internals, not as a public raw endpoint.
