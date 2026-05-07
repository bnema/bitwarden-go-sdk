// Package errors owns core use cases for error types and handling.
//
// Core packages must not import adapters.
package errors

import (
	stderrors "errors"
	"fmt"
	"strings"
)

// Kind classifies errors into stable categories.
type Kind string

// Stable error kinds used across the SDK.
const (
	KindUnknown           Kind = "unknown"
	KindUnauthenticated   Kind = "unauthenticated"
	KindPermissionDenied  Kind = "permission_denied"
	KindNotFound          Kind = "not_found"
	KindConflict          Kind = "conflict"
	KindValidation        Kind = "validation"
	KindRateLimited       Kind = "rate_limited"
	KindUnavailable       Kind = "unavailable"
	KindTemporary         Kind = "temporary"
	KindNetwork           Kind = "network"
	KindTwoFactorRequired Kind = "two_factor_required"
	KindCrypto            Kind = "crypto"
	KindLocked            Kind = "locked"
	KindUnsupported       Kind = "unsupported"
)

// Error is a structured error carrying safe metadata and an optional cause.
type Error struct {
	Kind               Kind
	Op                 string
	Status             int
	Code               string
	Message            string
	RetryAfter         int
	TwoFactorProviders []string
	Cause              error
}

// Error produces a safe string without exposing Cause text, because causes
// may contain secrets.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("bitwarden error")
	if e.Kind != "" {
		b.WriteString(": kind=")
		b.WriteString(string(e.Kind))
	}
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
	if e.Status > 0 {
		fmt.Fprintf(&b, " status=%d", e.Status)
	}
	if e.RetryAfter > 0 {
		fmt.Fprintf(&b, " retry_after=%d", e.RetryAfter)
	}
	if len(e.TwoFactorProviders) > 0 {
		b.WriteString(" providers=")
		b.WriteString(strings.Join(e.TwoFactorProviders, ","))
	}
	return b.String()
}

// Unwrap returns the wrapped cause for standard-library error inspection.
func (e *Error) Unwrap() error {
	return e.Cause
}

// Is enables errors.Is matching by Kind.
//
//	errors.Is(err, &Error{Kind: KindRateLimited}) // true when Kind matches
func (e *Error) Is(target error) bool {
	if target == nil {
		return false
	}
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// Is walks the error chain via Unwrap and returns true when any *Error in the
// chain has the requested Kind.
func Is(err error, kind Kind) bool {
	for err != nil {
		var e *Error
		if stderrors.As(err, &e) {
			if e.Kind == kind {
				return true
			}
			err = e.Cause
			continue
		}
		err = stderrors.Unwrap(err)
	}
	return false
}
