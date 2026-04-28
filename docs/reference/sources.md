# Sources

## Local official client clone

- Path: `/home/brice/dev/clone/clients`
- Observed commit during design: `91d233be9ba48da556b5b450782be1aa00b1a10e`
- Remote: `https://github.com/bitwarden/clients.git`

Important files already identified:

- `libs/common/src/services/api.service.ts`
- `libs/common/src/abstractions/api.service.ts`
- `libs/common/src/platform/services/default-environment.service.ts`
- `libs/common/src/auth/password-prelogin/password-prelogin-api.service.ts`
- `libs/common/src/auth/services/account-api.service.ts`
- `libs/common/src/platform/services/config/config-api.service.ts`
- `libs/common/src/vault/services/folder/folder-api.service.ts`
- `libs/common/src/vault/services/cipher.service.ts`
- `libs/common/src/platform/services/file-upload/bitwarden-file-upload.service.ts`
- `libs/common/src/key-management/master-password/services/master-password.service.ts`
- `libs/common/src/key-management/master-password/types/master-password.types.ts`
- `libs/common/src/platform/services/sdk/default-sdk.service.ts`

## Source citation rule

Every mapped endpoint or crypto flow must include:

- local file path;
- source commit or tag when available;
- line range or function name;
- whether the source is client, server, CLI, or public docs.
