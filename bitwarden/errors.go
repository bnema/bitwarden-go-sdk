package bitwarden

import (
	stderrors "errors"
	"fmt"
	"strings"
	"time"

	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
)

// ErrorKind classifies public errors into stable, sentinel-matchable categories.
type ErrorKind string

// Error implements the error interface so ErrorKind values can be used as
// targets in errors.Is calls.
func (k ErrorKind) Error() string {
	return "bitwarden: " + string(k)
}

const (
	// ErrorKindUnauthorized indicates authentication is required or invalid.
	ErrorKindUnauthorized ErrorKind = "unauthorized"
	// ErrorKindTwoFactorRequired indicates a two-factor challenge is required.
	ErrorKindTwoFactorRequired ErrorKind = "two-factor required"
	// ErrorKindLocked indicates the client is locked.
	ErrorKindLocked ErrorKind = "client locked"
	// ErrorKindNotFound indicates the requested resource was not found.
	ErrorKindNotFound ErrorKind = "not found"
	// ErrorKindDecryptionFailed indicates ciphertext could not be decrypted.
	ErrorKindDecryptionFailed ErrorKind = "decryption failed"
	// ErrorKindRateLimited indicates the service rate-limited the request.
	ErrorKindRateLimited ErrorKind = "rate limited"
	// ErrorKindUnsupported indicates scaffold behavior has not been implemented.
	ErrorKindUnsupported ErrorKind = "unsupported operation"
	// ErrorKindPermissionDenied indicates the request is forbidden.
	ErrorKindPermissionDenied ErrorKind = "permission denied"
	// ErrorKindConflict indicates a resource conflict (e.g. version mismatch).
	ErrorKindConflict ErrorKind = "conflict"
	// ErrorKindValidation indicates invalid input.
	ErrorKindValidation ErrorKind = "validation"
	// ErrorKindUnavailable indicates the service is temporarily unavailable.
	ErrorKindUnavailable ErrorKind = "unavailable"
	// ErrorKindTemporary indicates a transient error that can be retried.
	ErrorKindTemporary ErrorKind = "temporary"
	// ErrorKindNetwork indicates a network-level error.
	ErrorKindNetwork ErrorKind = "network"
	// ErrorKindUnknown indicates an unclassified error.
	ErrorKindUnknown ErrorKind = "unknown"
)

// Sentinels are public error values that support errors.Is matching.
// They carry only a Kind field so errors.Is works through the Error.Is method.
var (
	ErrUnauthorized      = &Error{Kind: ErrorKindUnauthorized}
	ErrTwoFactorRequired = &Error{Kind: ErrorKindTwoFactorRequired}
	ErrLocked            = &Error{Kind: ErrorKindLocked}
	ErrNotFound          = &Error{Kind: ErrorKindNotFound}
	ErrDecryptionFailed  = &Error{Kind: ErrorKindDecryptionFailed}
	ErrRateLimited       = &Error{Kind: ErrorKindRateLimited}
	ErrUnsupported       = &Error{Kind: ErrorKindUnsupported}
)

// Error is a structured public error carrying safe metadata.
// It supports errors.Is (by Kind or ErrorKind), errors.As, and errors.Unwrap.
// The wrapped cause is unexported to prevent accidental exposure.
type Error struct {
	Kind               ErrorKind
	Op                 string
	StatusCode         int
	Code               string
	Message            string
	RetryAfter         time.Duration
	TwoFactorProviders []TwoFactorProvider

	cause error
}

// Error produces a safe message. Cause text is never included because causes
// may contain secrets.
func (e *Error) Error() string {
	if e == nil {
		return "bitwarden: error"
	}
	var b strings.Builder
	b.WriteString("bitwarden: ")
	b.WriteString(string(e.Kind))
	if e.Op != "" {
		b.WriteString(" op=")
		b.WriteString(e.Op)
	}
	if e.Code != "" {
		b.WriteString(" code=")
		b.WriteString(e.Code)
	}
	if e.Message != "" {
		b.WriteString(" message=")
		b.WriteString(e.Message)
	}
	if e.StatusCode > 0 {
		fmt.Fprintf(&b, " status=%d", e.StatusCode)
	}
	if e.RetryAfter > 0 {
		fmt.Fprintf(&b, " retry_after=%v", e.RetryAfter)
	}
	if len(e.TwoFactorProviders) > 0 {
		b.WriteString(" providers=[")
		for i, p := range e.TwoFactorProviders {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(string(p))
		}
		b.WriteByte(']')
	}
	return b.String()
}

// Unwrap returns the wrapped cause for errors.Is / errors.As inspection.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Is enables errors.Is matching by Kind (when target is *Error) or by
// ErrorKind (when target is an ErrorKind value).
func (e *Error) Is(target error) bool {
	if target == nil || e == nil {
		return false
	}
	switch t := target.(type) {
	case *Error:
		return e.Kind == t.Kind
	case ErrorKind:
		return e.Kind == t
	}
	return false
}

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
	// TwoFactorProviderYubiKey identifies YubiKey challenges.
	TwoFactorProviderYubiKey TwoFactorProvider = "yubikey"
	// TwoFactorProviderDuo identifies Duo challenges.
	TwoFactorProviderDuo TwoFactorProvider = "duo"
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

// mapCoreError converts an internal/core/errors error into the public Error
// type. Non-core errors and nil are passed through unchanged.
func mapCoreError(err error) error {
	if err == nil {
		return nil
	}
	var core *coreerrors.Error
	if !stderrors.As(err, &core) {
		return err
	}

	pub := &Error{
		Kind:       mapCoreKind(core.Kind),
		Op:         core.Op,
		StatusCode: core.Status,
		Code:       core.Code,
		Message:    core.Message,
		cause:      core.Cause,
	}
	if core.RetryAfter > 0 {
		pub.RetryAfter = time.Duration(core.RetryAfter) * time.Second
	}
	if len(core.TwoFactorProviders) > 0 {
		pub.TwoFactorProviders = make([]TwoFactorProvider, len(core.TwoFactorProviders))
		for i, s := range core.TwoFactorProviders {
			pub.TwoFactorProviders[i] = mapTwoFactorProvider(s)
		}
	}
	return pub
}

// mapCoreKind converts an internal Kind to the public ErrorKind.
func mapCoreKind(k coreerrors.Kind) ErrorKind {
	switch k {
	case coreerrors.KindUnauthenticated:
		return ErrorKindUnauthorized
	case coreerrors.KindTwoFactorRequired:
		return ErrorKindTwoFactorRequired
	case coreerrors.KindLocked:
		return ErrorKindLocked
	case coreerrors.KindNotFound:
		return ErrorKindNotFound
	case coreerrors.KindRateLimited:
		return ErrorKindRateLimited
	case coreerrors.KindCrypto:
		return ErrorKindDecryptionFailed
	case coreerrors.KindUnsupported:
		return ErrorKindUnsupported
	case coreerrors.KindPermissionDenied:
		return ErrorKindPermissionDenied
	case coreerrors.KindConflict:
		return ErrorKindConflict
	case coreerrors.KindValidation:
		return ErrorKindValidation
	case coreerrors.KindUnavailable:
		return ErrorKindUnavailable
	case coreerrors.KindTemporary:
		return ErrorKindTemporary
	case coreerrors.KindNetwork:
		return ErrorKindNetwork
	default:
		return ErrorKindUnknown
	}
}

// mapTwoFactorProvider converts a core provider string (or numeric string) to
// a public TwoFactorProvider constant.
func mapTwoFactorProvider(s string) TwoFactorProvider {
	switch s {
	case "authenticator", "0":
		return TwoFactorProviderAuthenticator
	case "email", "1":
		return TwoFactorProviderEmail
	case "yubikey", "2":
		return TwoFactorProviderYubiKey
	case "duo", "3":
		return TwoFactorProviderDuo
	default:
		return TwoFactorProvider(s)
	}
}
