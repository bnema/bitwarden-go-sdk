# Cipher Crypto

## v0.1.0 status

Status: `Mapped`

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/models/domain/cipher.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: `Cipher.decrypt`
- Lines: `134-210`
- Role: cipher decrypt field flow and cipher-key selection.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/services/cipher.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: cipher encrypt helpers
- Lines: `421-430`, `2158-2180`, `2220-2235`, `2358-2409`
- Role: encrypted field mapping for login, secure note, fields, cipher keys.

## Behavior

- Use the user key by default.
- If a cipher-specific key exists, unwrap it using the user/org key and decrypt item fields with the cipher key.
- Decrypt top-level `name` and `notes`, then type-specific data, fields, password history, and attachment metadata.
- Login fields encrypt/decrypt username, password, TOTP, URI values, and URI checksums.
- Custom field names and values are encrypted; boolean field values normalize non-`true` values to `false`.
- On decrypt failure, official clients mark decryption failure and use `[error: cannot decrypt]` as the name sentinel. The Go SDK should map failures to safe crypto errors and avoid logging plaintext or ciphertext bodies.

## Fixtures

- `testdata/bitwarden/crypto/cipher_vectors.json`
- `testdata/bitwarden/crypto/folder_vectors.json`
