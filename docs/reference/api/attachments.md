# Attachments API

## v0.1.0 status

Status: `Mapped`

## Source mapping

- Source: `/home/brice/dev/clone/clients/libs/common/src/services/api.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbols: attachment metadata/upload/download/delete methods
- Lines: `542-634`
- Role: official attachment endpoint contracts.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/models/request/attachment.request.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `AttachmentRequest`
- Lines: `3-9`
- Role: official attachment request DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/models/response/attachment.response.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `AttachmentResponse`
- Lines: `3-18`
- Role: attachment metadata/download URL DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/models/response/attachment-upload-data.response.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `AttachmentUploadDataResponse`
- Lines: `8-25`
- Role: upload-init response DTO.

- Source: `/home/brice/dev/clone/clients/libs/common/src/platform/services/file-upload/azure-file-upload.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `AzureFileUploadService`
- Lines: `8-120`
- Role: external/Azure upload behavior and renew flow.

- Source: `/home/brice/dev/clone/clients/libs/common/src/vault/services/file-upload/cipher-file-upload.service.ts`
- Commit: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Symbol: `CipherFileUploadService`
- Lines: `31-104`
- Role: upload orchestration and rollback behavior.

## Endpoints

| Operation | Method/path | Notes |
| --- | --- | --- |
| Metadata/download URL | `GET /ciphers/{cipherId}/attachment/{attachmentId}` | Returns `AttachmentResponse`. |
| Upload init | `POST /ciphers/{id}/attachment/v2` | Body `AttachmentRequest`; returns `AttachmentUploadDataResponse`. |
| Direct upload | `POST /ciphers/{id}/attachment/{attachmentId}` | Multipart/form-data field `data`. |
| Renew upload URL | `GET /ciphers/{id}/attachment/{attachmentId}/renew` | Returns `AttachmentUploadDataResponse`. |
| Delete | `DELETE /ciphers/{id}/attachment/{attachmentId}` | Returns `DeleteAttachmentResponse`. |

Admin/emergency-access/share endpoints are not part of v0.1.0 public personal-account scope.

## Upload variants

| FileUploadType | Meaning |
| --- | --- |
| `0` Direct | Upload encrypted content back to Bitwarden using multipart field `data`. |
| `1` Azure | PUT encrypted content to the returned external URL; large files may use block upload and URL renew. |

Upload failure triggers rollback by deleting the newly-created attachment metadata.

## DTO fields

- `AttachmentRequest`: `fileName`, `key`, `fileSize`, `adminRequest`, `lastKnownRevisionDate`.
- `AttachmentResponse`: `Id`, `Url`, `FileName`, `Key`, `Size`, `SizeName`.
- `AttachmentUploadDataResponse`: `AttachmentId`, `FileUploadType`, `CipherResponse`, `CipherMiniResponse`, `Url`.
- `DeleteAttachmentResponse`: updated `Cipher`.

## Fixtures

- `testdata/bitwarden/attachments/attachment_request.json`
- `testdata/bitwarden/attachments/attachment_response.json`
- `testdata/bitwarden/attachments/attachment_upload_direct_response.json`
- `testdata/bitwarden/attachments/attachment_upload_azure_response.json`
- `testdata/bitwarden/attachments/attachment_delete_response.json`
