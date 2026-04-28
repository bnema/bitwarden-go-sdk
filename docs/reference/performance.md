# Performance Requirements

## V1 status

Status: `In V1`

## Goals

- Fast startup and login.
- Fast initial sync.
- Efficient incremental and background sync.
- Bounded parallel decryption.
- Low-latency in-memory list and search after unlock.
- Benchmarks for auth, sync, decrypt, list, and search paths.

## Constraints

- Concurrency must be bounded and race-safe.
- No CLI-style blocking behavior.
- No persistent decrypted search index by default.
- No network calls in default unit tests.
