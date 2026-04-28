# Login With Master Password

## V1 status

Status: `In V1`

## Purpose

Authenticate with email and master password after deriving the correct Bitwarden authentication hash locally.

## Evidence to map

- Client source: `libs/common/src/services/api.service.ts`
- Crypto source: `libs/common/src/key-management/master-password/services/master-password.service.ts`
- Server source: not mapped yet

## SDK implication

`Client.Login` must orchestrate prelogin, crypto derivation, identity token request, 2FA handling, token storage, and in-memory unlock state.
