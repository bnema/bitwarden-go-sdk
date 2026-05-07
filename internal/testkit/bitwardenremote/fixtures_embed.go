package bitwardenremote

// Embedded fixture responses for the test server. These are inlined to avoid
// filesystem path issues when tests run from different working directories.

const preloginResponsePbkdf2 = `{"Kdf":0,"KdfIterations":600000}`

const tokenSuccessResponse = `{
  "access_token": "sanitized-access-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "sanitized-refresh-token",
  "PrivateKey": null,
  "AccountKeys": null,
  "Key": "2.sanitized-iv|sanitized-ciphertext|sanitized-mac",
  "TwoFactorToken": null,
  "Kdf": 0,
  "KdfIterations": 600000,
  "KdfMemory": null,
  "KdfParallelism": null,
  "ForcePasswordReset": false,
  "ApiUseKeyConnector": false,
  "MasterPasswordPolicy": null,
  "UserDecryptionOptions": null,
  "AccountId": "user-id-1"
}`

const tokenRefreshResponse = `{
  "access_token": "sanitized-new-access-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "sanitized-new-refresh-token",
  "AccountId": "user-id-1"
}`

// ---------------------------------------------------------------------------
// Vault / account / sync / cipher / folder / attachment fixtures
// ---------------------------------------------------------------------------

const configResponse = `{"version":"test","featureFlags":{}}`

const accountProfileResponse = `{
  "Id": "user-id-1",
  "Name": "Sanitized User",
  "Email": "user@example.com",
  "EmailVerified": true,
  "Premium": true,
  "PremiumFromOrganization": false,
  "Culture": "en-US",
  "TwoFactorEnabled": true,
  "Key": "2.sanitized-iv|sanitized-user-key|sanitized-mac",
  "AvatarColor": "#3366cc",
  "CreationDate": "2026-01-01T00:00:00Z",
  "PrivateKey": null,
  "AccountKeys": null,
  "SecurityStamp": "sanitized-security-stamp",
  "ForcePasswordReset": false,
  "UsesKeyConnector": false,
  "VerifyDevices": true,
  "Organizations": [],
  "Providers": [],
  "ProviderOrganizations": []
}`

const subscriptionResponse = `{
  "StorageName": "Personal",
  "StorageGb": 1,
  "MaxStorageGb": 1,
  "License": null,
  "Expiration": null,
  "Subscription": null,
  "UpcomingInvoice": null,
  "CustomerDiscount": null
}`

const syncResponsePersonal = `{
  "Profile": {
    "Id": "user-id-1",
    "Name": "Sanitized User",
    "Email": "user@example.com",
    "EmailVerified": true,
    "Premium": true,
    "PremiumFromOrganization": false,
    "TwoFactorEnabled": true,
    "Key": "2.sanitized-iv|sanitized-user-key|sanitized-mac"
  },
  "Folders": [
    { "Id": "folder-id-1", "Name": "2.sanitized-iv|sanitized-folder-name|sanitized-mac", "RevisionDate": "2026-01-01T00:00:00Z" }
  ],
  "Ciphers": [
    { "Id": "cipher-id-1", "Type": 1, "Name": "2.sanitized-iv|sanitized-name|sanitized-mac", "Favorite": false, "RevisionDate": "2026-01-01T00:00:00Z" }
  ],
  "Domains": null,
  "Policies": [],
  "Sends": [],
  "UserDecryption": null
}`

const revisionDateResponse = `1704067200000`

const cipherResponseLogin = `{
  "Id": "cipher-id-1",
  "OrganizationId": null,
  "FolderId": "folder-id-1",
  "Type": 1,
  "Name": "2.sanitized-iv|sanitized-name|sanitized-mac",
  "Notes": "2.sanitized-iv|sanitized-notes|sanitized-mac",
  "Favorite": false,
  "Edit": true,
  "ViewPassword": true,
  "RevisionDate": "2026-01-01T00:00:00Z",
  "CreationDate": "2026-01-01T00:00:00Z",
  "DeletedDate": null,
  "ArchivedDate": null,
  "Login": {
    "Username": "2.sanitized-iv|sanitized-username|sanitized-mac",
    "Password": "2.sanitized-iv|sanitized-password|sanitized-mac",
    "Totp": "2.sanitized-iv|sanitized-totp|sanitized-mac",
    "Uris": [
      { "Uri": "2.sanitized-iv|sanitized-uri|sanitized-mac", "Match": null, "UriChecksum": "2.sanitized-iv|sanitized-checksum|sanitized-mac" }
    ]
  },
  "Fields": [],
  "Attachments": [],
  "PasswordHistory": [],
  "Reprompt": 0,
  "Key": null
}`

const cipherRestoreResponse = `{
  "Id": "cipher-id-1",
  "Type": 1,
  "Name": "2.sanitized-iv|sanitized-name|sanitized-mac",
  "DeletedDate": null,
  "RevisionDate": "2026-01-02T00:00:00Z"
}`

const folderResponseFixture = `{
  "Id": "folder-id-1",
  "Name": "2.sanitized-iv|sanitized-folder-name|sanitized-mac",
  "RevisionDate": "2026-01-01T00:00:00Z"
}`

const attachmentUploadDirectResponse = `{
  "AttachmentId": "attachment-id-1",
  "FileUploadType": 0,
  "CipherResponse": { "Id": "cipher-id-1", "RevisionDate": "2026-01-02T00:00:00Z" },
  "CipherMiniResponse": null,
  "Url": null
}`

const accountRevisionDateResponse = `1704067200000`

// attachmentUploadAzureResponseTemplate uses %s for the base URL so that the
// test server can inject its own address, making external uploads self-contained.
const attachmentUploadAzureResponseTemplate = `{
  "AttachmentId": "attachment-id-1",
  "FileUploadType": 1,
  "CipherResponse": { "Id": "cipher-id-1", "RevisionDate": "2026-01-02T00:00:00Z" },
  "CipherMiniResponse": null,
  "Url": "%s/external-attachment-upload/attachment-id-1"
}`

// attachmentMetadataResponseTemplate uses %s for the server base URL so the
// download URL points back to the test server, making it self-contained.
const attachmentMetadataResponseTemplate = `{
  "Id": "attachment-id-1",
  "Url": "%s/attachment-download/attachment-id-1",
  "FileName": "2.sanitized-iv|sanitized-file-name|sanitized-mac",
  "Key": "2.sanitized-iv|sanitized-attachment-key|sanitized-mac",
  "Size": 128,
  "SizeName": "128 B"
}`

const attachmentUploadDataRenewResponse = `{
  "AttachmentId": "attachment-id-1",
  "FileUploadType": 0,
  "CipherResponse": null,
  "CipherMiniResponse": null,
  "Url": null
}`

const attachmentDeleteResponse = `{
  "Cipher": {
    "Id": "cipher-id-1",
    "RevisionDate": "2026-01-03T00:00:00Z",
    "Attachments": []
  }
}`
