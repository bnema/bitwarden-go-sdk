# Ciphers API

## v0.1.0 status

Status: `Mapped`

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/services/api.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: cipher get/create/update/delete/restore methods
- Lines: `384-460`, `491-539`
- Role: official cipher endpoint contracts.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/models/response/cipher.response.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `CipherResponse`
- Lines: `22-93`
- Role: official cipher response DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/models/request/cipher.request.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: `CipherRequest`, subtype requests
- Lines: `19-53`, `180-212`
- Role: official cipher request DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/services/cipher.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: delete/trash/restore local semantics
- Lines: `1450-1487`, `1619-1765`
- Role: client mutation semantics.

## Personal-account endpoints

| Operation | Method/path | Notes |
| --- | --- | --- |
| Get | `GET /ciphers/{id}` | Returns `CipherResponse`. |
| Get details | `GET /ciphers/{id}/details` | Returns `CipherResponse`. |
| Create | `POST /ciphers` | Body `CipherRequest`; returns `CipherResponse`. |
| Create v2 | `POST /ciphers/create` | Body `{ cipher, collectionIds }`; returns `CipherResponse`. |
| Update | `PUT /ciphers/{id}` | Body `CipherRequest`; returns `CipherResponse`. |
| Partial update | `PUT /ciphers/{id}/partial` | Body `CipherPartialRequest`; returns `CipherResponse`. |
| Move | `PUT /ciphers/move` | Body `{ ids, folderId }`. |
| Soft delete/trash | `PUT /ciphers/{id}/delete` | Marks deleted. |
| Restore | `PUT /ciphers/{id}/restore` | Returns `CipherResponse`. |
| Permanent delete | `DELETE /ciphers/{id}` | Removes cipher. |
| Bulk soft delete | `PUT /ciphers/delete` | Body `{ ids, organizationId? }`. |
| Bulk restore | `PUT /ciphers/restore` | Body `{ ids, organizationId? }`; returns list response. |
| Bulk permanent delete | `DELETE /ciphers` | Body `{ ids, organizationId? }`. |

Admin/organization endpoint variants are out of v0.1.0 public scope.

## DTO fields

`CipherResponse` includes `Id`, `OrganizationId`, `FolderId`, `Type`, `Name`, `Notes`, `Favorite`, `Edit`, `ViewPassword`, `Permissions`, `OrganizationUseTotp`, `RevisionDate`, `CollectionIds`, `CreationDate`, `DeletedDate`, `ArchivedDate`, subtype DTOs (`Login`, `Card`, `Identity`, `SecureNote`, `SshKey`), `Fields`, `Attachments`, `PasswordHistory`, `Reprompt`, and `Key`.

`CipherRequest` includes encrypted type fields, folder/org IDs, `lastKnownRevisionDate`, `archivedDate`, `reprompt`, and optional cipher `key`.

## SDK implications

- Public API supports personal ciphers only.
- Soft delete/trash, restore, and permanent delete must be explicit operations.
- Local snapshot updates only after successful remote operation.
- Raw request/response DTOs remain internal.

## Fixtures

- `testdata/bitwarden/ciphers/cipher_response_login.json`
- `testdata/bitwarden/ciphers/cipher_create_request_login.json`
- `testdata/bitwarden/ciphers/cipher_restore_response.json`
- `testdata/bitwarden/ciphers/cipher_bulk_delete_request.json`
