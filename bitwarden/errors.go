package bitwarden

import (
	"errors"
	"time"
)

var (
	ErrUnauthorized      = errors.New("bitwarden: unauthorized")
	ErrTwoFactorRequired = errors.New("bitwarden: two-factor required")
	ErrLocked            = errors.New("bitwarden: client locked")
	ErrNotFound          = errors.New("bitwarden: not found")
	ErrDecryptionFailed  = errors.New("bitwarden: decryption failed")
	ErrRateLimited       = errors.New("bitwarden: rate limited")
	ErrUnsupported       = errors.New("bitwarden: unsupported operation")
)

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

type TwoFactorProvider string

const (
	TwoFactorProviderAuthenticator TwoFactorProvider = "authenticator"
	TwoFactorProviderEmail         TwoFactorProvider = "email"
)

type TwoFactorError struct {
	Providers []TwoFactorProvider
}

func (e *TwoFactorError) Error() string {
	return ErrTwoFactorRequired.Error()
}

func (e *TwoFactorError) Unwrap() error {
	return ErrTwoFactorRequired
}
