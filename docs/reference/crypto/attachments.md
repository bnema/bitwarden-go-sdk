# Attachment Crypto

## v0.1.0 status

Status: `Mapped`

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/models/domain/attachment.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `Attachment.decrypt`
- Lines: `36-76`
- Role: attachment filename decrypt and key unwrap behavior.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/services/cipher.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `encryptAttachmentData`
- Lines: `384-403`
- Role: attachment metadata encryption.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/services/default-cipher-encryption.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `decryptAttachmentData`
- Lines: `300-320`
- Role: attachment content decrypt handoff to SDK.

- Source: `/home/brice/dev/clone/sdk-internal/crates/bitwarden-wasm-internal/src/pure_crypto.rs`
- Commit: `3aa1201692e5d56efa763c7dec1161254d4c9e4b`
- Symbols: `symmetric_encrypt_filedata`, `symmetric_decrypt_filedata`
- Lines: `55-68`, `88-96`
- Role: official SDK file data encryption/decryption entry points.

## Behavior

- Attachment filename is encrypted/decrypted like a string field.
- Attachment key is wrapped with the cipher/user/org key and unwrapped before content encryption/decryption.
- Attachment content uses EncString buffer format for file data.
- The Go SDK must expose streaming upload/download APIs and avoid requiring full plaintext file contents in memory even though official JS/WASM APIs operate on buffers.

## Fixtures

- `testdata/bitwarden/crypto/attachment_vectors.json`
