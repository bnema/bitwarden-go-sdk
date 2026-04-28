# EncString

## v0.1.0 status

Status: `Mapped`

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/platform/enums/encryption-type.enum.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `EncryptionType`
- Lines: `3-18`, `28-49`
- Role: TypeScript client encryption-type IDs and serialized part counts.

- Source: `/home/brice/dev/clone/clients/libs/common/src/key-management/crypto/models/enc-string.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `EncString`
- Lines: `73-88`, `129-149`
- Role: TypeScript client parser/serializer.

- Source: `/home/brice/dev/clone/sdk-internal/crates/bitwarden-crypto/src/enc_string/symmetric.rs`
- Commit: `3aa1201692e5d56efa763c7dec1161254d4c9e4b`
- Symbols: `EncString::from_str`, `EncString::from_buffer`, `EncString::to_buffer`, `ToString`
- Lines: `64-88`, `98-132`, `143-190`, `220-230`
- Role: official SDK symmetric EncString parsing and serialization.

## Supported symmetric forms for v0.1.0

| Type | Name | Text format | Buffer format |
| --- | --- | --- | --- |
| `0` | AES-256-CBC | `0.<iv>|<data>` | `0x00 || iv(16) || data` |
| `2` | AES-256-CBC-HMAC-SHA256 | `2.<iv>|<data>|<mac>` | `0x02 || iv(16) || mac(32) || data` |
| `7` | COSE_Encrypt0 | `7.<data>` | `0x07 || cose_encrypt0_bytes` |

Type `2` is the primary modern Bitwarden symmetric form. Type `0` is legacy and is accepted only where official source requires legacy support. RSA forms are not part of personal-account vault item symmetric encryption for v0.1.0.

## Fixtures

- `testdata/bitwarden/crypto/enc_string_vectors.json`
