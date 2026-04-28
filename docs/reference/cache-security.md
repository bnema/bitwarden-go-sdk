# Cache and Security Model

## V1 status

Status: `In V1`

## Threat model

Assume an attacker may read files in the user's home directory.

## Defaults

- No plaintext disk cache.
- No persistent decrypted search index.
- No persisted master key or user key.
- No persisted plaintext ciphers, folders, attachments, passwords, usernames, or URIs.
- No HTTP body dumps.
- No secret-bearing logs.

## SDK role

The SDK does not provide disk persistence. Runtime OAuth tokens live in an internal in-memory store and decrypted vault data is held only in memory while the client is unlocked.

Consumers such as `gtk4ls-bitwarden` own application-specific persistent cache policy unless a future SDK adapter is explicitly designed and threat-modeled.
