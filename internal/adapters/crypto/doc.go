// Package crypto will contain the concrete Bitwarden cryptography
// implementation after KDF, EncString, user-key, cipher, and attachment flows
// are source-mapped.
//
// It must use Go secret-memory facilities where appropriate and must avoid
// leaking plaintext values through logs or persistent storage.
package crypto
