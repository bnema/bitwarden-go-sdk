package bitwarden

import (
	"errors"
	"time"
)

var (
	// ErrUnauthorized indicates authentication is required or invalid.
	ErrUnauthorized = errors.New("bitwarden: unauthorized")
	// ErrTwoFactorRequired indicates a two-factor challenge is required.
	ErrTwoFactorRequired = errors.New("bitwarden: two-factor required")
	// ErrLocked indicates the client is locked.
	ErrLocked = errors.New("bitwarden: client locked")
	// ErrNotFound indicates the requested resource was not found.
	ErrNotFound = errors.New("bitwarden: not found")
	// ErrDecryptionFailed indicates ciphertext could not be decrypted.
	ErrDecryptionFailed = errors.New("bitwarden: decryption failed")
	// ErrRateLimited indicates the service rate-limited the request.
	ErrRateLimited = errors.New("bitwarden: rate limited")
	// ErrUnsupported indicates scaffold behavior has not been implemented.
	ErrUnsupported = errors.New("bitwarden: unsupported operation")
)

// APIError represents a Bitwarden API error response.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e == nil {
		return "bitwarden: api error"
	}
	if e.Code != "" {
		return "bitwarden: api error " + e.Code
	}
	return "bitwarden: api error"
}

// TwoFactorProvider identifies a supported two-factor method.
type TwoFactorProvider string

const (
	// TwoFactorProviderAuthenticator identifies authenticator-app challenges.
	TwoFactorProviderAuthenticator TwoFactorProvider = "authenticator"
	// TwoFactorProviderEmail identifies email challenges.
	TwoFactorProviderEmail TwoFactorProvider = "email"
)

// TwoFactorError reports that two-factor authentication is required.
type TwoFactorError struct {
	Providers []TwoFactorProvider
}

func (e *TwoFactorError) Error() string {
	return ErrTwoFactorRequired.Error()
}

func (e *TwoFactorError) Unwrap() error {
	return ErrTwoFactorRequired
}
