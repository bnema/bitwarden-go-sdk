# User Key

## v0.1.0 status

Status: `Mapped`

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/key-management/master-password/services/master-password.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: `makeMasterKey`, `makeMasterKeyHash`, `decryptUserKeyWithMasterKey`
- Lines: `230-244`, `259-277`, `286-330`
- Role: official client master-password/user-key flow.

- Source: `/home/brice/dev/clone/sdk-internal/crates/bitwarden-crypto/src/keys/master_key.rs`
- Commit: `3aa1201692e5d56efa763c7dec1161254d4c9e4b`
- Symbols: `MasterKey::derive_master_key_hash`, `encrypt_user_key`, `decrypt_user_key`, tests
- Lines: `55-75`, `129-164`, `191-337`
- Role: official SDK auth hash and user-key unwrap behavior.

- Source: `/home/brice/dev/clone/sdk-internal/crates/bitwarden-crypto/src/aes.rs`
- Commit: `3aa1201692e5d56efa763c7dec1161254d4c9e4b`
- Symbols: `encrypt_aes256_hmac`, `decrypt_aes256_hmac`, `generate_mac`
- Lines: `38-73`, `92-103`
- Role: AES-CBC-HMAC primitive behavior.

## Behavior

- Master key derives from password and normalized email/KDF.
- Server auth hash is PBKDF2-HMAC-SHA256 over master-key bytes with the master password as salt and purpose `ServerAuthorization = 1`, then base64 encoded.
- User keys are encrypted with a stretched master key using AES-256-CBC-HMAC-SHA256 EncString type `2` for modern accounts.
- Legacy user keys encrypted as EncString type `0` remain decryptable where source requires.
- Failed user-key decrypt maps to a crypto/invalid-key error.

## Fixtures

- `testdata/bitwarden/crypto/auth_hash_vectors.json`
- `testdata/bitwarden/crypto/user_key_vectors.json`
