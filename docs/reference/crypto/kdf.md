# KDF

## v0.1.0 status

Status: `Mapped`

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/key-management/src/models/kdf-config.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: `PBKDF2KdfConfig`, `Argon2idKdfConfig`
- Lines: `16-60`, `66-145`
- Role: official client KDF settings and SDK config mapping.

- Source: `/home/brice/dev/clone/clients/libs/common/src/key-management/crypto/key-generation/default-key-generation.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `DefaultKeyGenerationService.deriveKey`
- Lines: `53-64`
- Role: client delegates KDF derivation to SDK `PureCrypto`.

- Source: `/home/brice/dev/clone/sdk-internal/crates/bitwarden-crypto/src/keys/kdf.rs`
- Commit: `3aa1201692e5d56efa763c7dec1161254d4c9e4b`
- Symbols: `KdfDerivedKeyMaterial::derive_kdf_key`, `dangerous_derive_kdf_material`, tests
- Lines: `32-94`, `110-119`, `180-259`
- Role: official SDK KDF implementation and deterministic test vectors.

## KDF IDs

| ID | Name | Parameters |
| --- | --- | --- |
| `0` | PBKDF2-SHA256 | iterations |
| `1` | Argon2id | iterations, memory MiB, parallelism |

## Behavior

- Master-password salt is normalized email: trim and lower-case before derivation.
- PBKDF2 uses HMAC-SHA256 and returns 32 bytes.
- Argon2id hashes `SHA256(salt)` as the Argon2 salt, uses Argon2id version `0x13`, and returns 32 bytes.
- Official SDK rejects PBKDF2 iterations below `5000`.
- Official SDK rejects Argon2id memory below `16` MiB, iterations below `2`, or parallelism below `1`.

## Fixtures

- `testdata/bitwarden/crypto/kdf_pbkdf2_vectors.json`
- `testdata/bitwarden/crypto/kdf_argon2id_vectors.json`
