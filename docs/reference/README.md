# Bitwarden SDK Reference

This directory is the source-backed reference for `bitwarden-go-sdk`.

The SDK implementation must follow these documents. If implementation research finds contradictory evidence, update the relevant reference page before changing code.

## Evidence priority

1. Official Bitwarden clients.
2. Official Bitwarden server handlers and contracts.
3. Bitwarden CLI behavior as a secondary reference.
4. Public docs as supporting context.

## Coverage statuses

- `Mapped` — source-mapped and understood.
- `In V1` — planned for initial SDK implementation.
- `Deferred` — recognized but not V1.
- `Out of scope` — intentionally excluded.
- `Unknown` — requires more verification.

## Safety rules

- Do not add HTTP body dumps.
- Do not document examples with real secrets or tokens.
- Do not store plaintext vault data in fixtures.
- Do not use live Bitwarden accounts for default tests.
