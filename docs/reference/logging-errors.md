# Logging and Errors

## V1 status

Status: `In V1`

## Logging policy

Logging is optional and disabled by default.

Allowed metadata:

- operation name;
- duration;
- region or environment type;
- item counts;
- error class;
- HTTP method and route template without body.

Forbidden data:

- master passwords;
- access tokens;
- refresh tokens;
- user keys;
- plaintext item names, usernames, passwords, URIs, notes, or fields;
- request bodies;
- response bodies;
- sensitive headers.

## Error model

Public errors must support `errors.Is` and `errors.As` for auth, 2FA, locked state, not found, decryption failure, rate limits, and API status details.

The SDK does not provide disk persistence. Runtime OAuth tokens are kept in an internal in-memory store and are zeroised when replaced or deleted. Applications that need persistence must add it outside the SDK boundary and must not log OAuth token values.
