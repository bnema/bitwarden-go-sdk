# Folders API

## v0.1.0 status

Status: `Mapped`

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/services/folder/folder-api.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `FolderApiService`
- Lines: `16-59`
- Role: official folder endpoint contracts.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/models/request/folder.request.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `FolderRequest`
- Lines: `3-12`
- Role: official encrypted folder request DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/models/response/folder.response.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `FolderResponse`
- Lines: `3-14`
- Role: official folder response DTO.

## Endpoints

| Operation | Method/path | Notes |
| --- | --- | --- |
| Get | `GET /folders/{id}` | Returns `FolderResponse`. |
| Create | `POST /folders` | Body `FolderRequest`; returns `FolderResponse`. |
| Update | `PUT /folders/{id}` | Body `FolderRequest`; returns `FolderResponse`. |
| Delete | `DELETE /folders/{id}` | Deletes one folder. |
| Delete all | `DELETE /folders/all` | Clears all personal folders; public exposure should be explicit if implemented. |

## DTO fields

- `FolderRequest.Name`: encrypted folder name.
- `FolderResponse.Id`: folder ID.
- `FolderResponse.Name`: encrypted folder name.
- `FolderResponse.RevisionDate`: revision timestamp.

## SDK implications

- The public API exposes decrypted folder names.
- HTTP DTOs carry encrypted names only.
- Folder create/update must encrypt `Name` before sending.
- Delete-all is source-mapped but should be exposed only if the public API intentionally includes a high-risk bulk operation.

## Fixtures

- `testdata/bitwarden/folders/folder_request.json`
- `testdata/bitwarden/folders/folder_response.json`
