package bitwarden

import (
	stderrors "errors"
	"fmt"
	"strings"
	"testing"
	"time"

	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
)

// --- Sentinels with errors.Is ---

func TestErrorsIsRateLimited(t *testing.T) {
	err := &Error{Kind: ErrorKindRateLimited}
	if !stderrors.Is(err, ErrRateLimited) {
		t.Fatal("errors.Is(err, ErrRateLimited) should be true")
	}
}

func TestErrorsIsUnauthorized(t *testing.T) {
	err := &Error{Kind: ErrorKindUnauthorized}
	if !stderrors.Is(err, ErrUnauthorized) {
		t.Fatal("errors.Is(err, ErrUnauthorized) should be true")
	}
}

func TestErrorsIsTwoFactorRequired(t *testing.T) {
	err := &Error{Kind: ErrorKindTwoFactorRequired}
	if !stderrors.Is(err, ErrTwoFactorRequired) {
		t.Fatal("errors.Is(err, ErrTwoFactorRequired) should be true")
	}
}

func TestErrorsIsLocked(t *testing.T) {
	err := &Error{Kind: ErrorKindLocked}
	if !stderrors.Is(err, ErrLocked) {
		t.Fatal("errors.Is(err, ErrLocked) should be true")
	}
}

func TestErrorsIsNotFound(t *testing.T) {
	err := &Error{Kind: ErrorKindNotFound}
	if !stderrors.Is(err, ErrNotFound) {
		t.Fatal("errors.Is(err, ErrNotFound) should be true")
	}
}

func TestErrorsIsDecryptionFailed(t *testing.T) {
	err := &Error{Kind: ErrorKindDecryptionFailed}
	if !stderrors.Is(err, ErrDecryptionFailed) {
		t.Fatal("errors.Is(err, ErrDecryptionFailed) should be true")
	}
}

func TestErrorsIsUnsupported(t *testing.T) {
	err := &Error{Kind: ErrorKindUnsupported}
	if !stderrors.Is(err, ErrUnsupported) {
		t.Fatal("errors.Is(err, ErrUnsupported) should be true")
	}
}

func TestSentinelSelfIs(t *testing.T) {
	// Sentinel compared to itself must always match.
	if !stderrors.Is(ErrRateLimited, ErrRateLimited) {
		t.Fatal("errors.Is(sentinel, sentinel) should be true")
	}
	if !stderrors.Is(ErrUnauthorized, ErrUnauthorized) {
		t.Fatal("errors.Is(sentinel, sentinel) should be true")
	}
}

// --- errors.As exposes StatusCode and RetryAfter ---

func TestErrorsAsStatusCodeRetryAfter(t *testing.T) {
	err := &Error{
		Kind:       ErrorKindRateLimited,
		StatusCode: 429,
		RetryAfter: 30 * time.Second,
	}
	var e *Error
	if !stderrors.As(err, &e) {
		t.Fatal("errors.As should succeed")
	}
	if e.StatusCode != 429 {
		t.Fatalf("StatusCode: got %d, want 429", e.StatusCode)
	}
	if e.RetryAfter != 30*time.Second {
		t.Fatalf("RetryAfter: got %v, want 30s", e.RetryAfter)
	}
}

// --- Two-factor provider mapping ---

func TestTwoFactorProvidersMap(t *testing.T) {
	providers := []TwoFactorProvider{
		TwoFactorProviderAuthenticator,
		TwoFactorProviderEmail,
		TwoFactorProviderYubiKey,
		TwoFactorProviderDuo,
	}
	// Verify all public provider constants are distinct and non-zero.
	seen := make(map[TwoFactorProvider]bool)
	for _, p := range providers {
		if p == "" {
			t.Fatal("TwoFactorProvider constant should not be empty")
		}
		if seen[p] {
			t.Fatalf("duplicate TwoFactorProvider: %q", p)
		}
		seen[p] = true
	}
}

// --- Public error text excludes secrets ---

func TestPublicErrorNoSecret(t *testing.T) {
	secret := "SECRET_SHOULD_NOT_APPEAR"
	cause := fmt.Errorf("%s", secret)
	err := &Error{
		Kind:    ErrorKindDecryptionFailed,
		Message: "crypto error",
		cause:   cause,
	}
	msg := err.Error()
	if strings.Contains(msg, secret) {
		t.Fatalf("Error() must not include cause text; got: %q", msg)
	}
	// Safe fields should appear.
	if !strings.Contains(msg, "crypto error") {
		t.Error("Error() should contain Message")
	}
	if !strings.Contains(msg, string(ErrorKindDecryptionFailed)) {
		t.Error("Error() should contain Kind")
	}
}

func TestPublicErrorUnwrap(t *testing.T) {
	cause := fmt.Errorf("inner")
	err := &Error{Kind: ErrorKindUnknown, cause: cause}
	if !stderrors.Is(err, cause) {
		t.Fatal("errors.Is should find unwrapped cause")
	}
}

// --- Existing ErrUnsupported behavior ---

func TestUnsupportedMethodsReturnSentinel_StillWorks(t *testing.T) {
	// Simulate the client returning ErrUnsupported directly.
	err := ErrUnsupported
	if !stderrors.Is(err, ErrUnsupported) {
		t.Fatal("errors.Is(ErrUnsupported, ErrUnsupported) must be true")
	}
}

// --- Error() output for sentinel ---

func TestSentinelErrorMessage(t *testing.T) {
	msg := ErrRateLimited.Error()
	if !strings.Contains(msg, "rate limited") {
		t.Fatalf("ErrRateLimited.Error() should mention 'rate limited'; got: %q", msg)
	}
}

func TestSentinelErrorMessageType(t *testing.T) {
	msg := ErrUnauthorized.Error()
	if !strings.Contains(msg, "unauthorized") {
		t.Fatalf("ErrUnauthorized.Error() should mention 'unauthorized'; got: %q", msg)
	}
}

// --- ErrorKind as an error ---

func TestErrorKindImplementsError(_ *testing.T) {
	var _ error = ErrorKindRateLimited
}

// --- Error.Is with ErrorKind target ---

func TestErrorIsByErrorKind(t *testing.T) {
	err := &Error{Kind: ErrorKindRateLimited}
	if !stderrors.Is(err, ErrorKindRateLimited) {
		t.Fatal("errors.Is(err, ErrorKindRateLimited) should be true")
	}
}

// --- ErrorKind does not match different kind ---

func TestErrorIsByErrorKindMismatch(t *testing.T) {
	err := &Error{Kind: ErrorKindNotFound}
	if stderrors.Is(err, ErrorKindRateLimited) {
		t.Fatal("errors.Is(err, ErrorKindRateLimited) should be false for not-found error")
	}
}

// --- mapCoreError tests (unexported, tested in-package) ---

func TestMapCoreErrorNil(t *testing.T) {
	if mapCoreError(nil) != nil {
		t.Fatal("mapCoreError(nil) should return nil")
	}
}

func TestMapCoreErrorRateLimited(t *testing.T) {
	core := &coreerrors.Error{
		Kind:       coreerrors.KindRateLimited,
		Status:     429,
		RetryAfter: 30,
	}
	mapped := mapCoreError(core)
	if !stderrors.Is(mapped, ErrRateLimited) {
		t.Fatal("mapped error should match ErrRateLimited")
	}
	var pub *Error
	if !stderrors.As(mapped, &pub) {
		t.Fatal("errors.As should succeed on mapped error")
	}
	if pub.StatusCode != 429 {
		t.Fatalf("StatusCode: got %d, want 429", pub.StatusCode)
	}
	if pub.RetryAfter != 30*time.Second {
		t.Fatalf("RetryAfter: got %v, want 30s", pub.RetryAfter)
	}
}

func TestMapCoreErrorTwoFactorWithStrings(t *testing.T) {
	core := &coreerrors.Error{
		Kind:               coreerrors.KindTwoFactorRequired,
		TwoFactorProviders: []string{"authenticator", "email", "yubikey", "duo"},
	}
	mapped := mapCoreError(core)
	if !stderrors.Is(mapped, ErrTwoFactorRequired) {
		t.Fatal("mapped error should match ErrTwoFactorRequired")
	}
	var pub *Error
	if !stderrors.As(mapped, &pub) {
		t.Fatal("errors.As should succeed on mapped error")
	}
	expected := []TwoFactorProvider{
		TwoFactorProviderAuthenticator,
		TwoFactorProviderEmail,
		TwoFactorProviderYubiKey,
		TwoFactorProviderDuo,
	}
	if len(pub.TwoFactorProviders) != len(expected) {
		t.Fatalf("providers count: got %d, want %d", len(pub.TwoFactorProviders), len(expected))
	}
	for i, p := range pub.TwoFactorProviders {
		if p != expected[i] {
			t.Errorf("provider[%d]: got %q, want %q", i, p, expected[i])
		}
	}
}

func TestMapCoreErrorTwoFactorWithNumericStrings(t *testing.T) {
	core := &coreerrors.Error{
		Kind:               coreerrors.KindTwoFactorRequired,
		TwoFactorProviders: []string{"0", "1", "2", "3"},
	}
	mapped := mapCoreError(core)
	var pub *Error
	if !stderrors.As(mapped, &pub) {
		t.Fatal("errors.As should succeed on mapped error")
	}
	expected := []TwoFactorProvider{
		TwoFactorProviderAuthenticator, // 0
		TwoFactorProviderEmail,         // 1
		TwoFactorProviderDuo,           // 2
		TwoFactorProviderYubiKey,       // 3
	}
	if len(pub.TwoFactorProviders) != len(expected) {
		t.Fatalf("providers count: got %d, want %d", len(pub.TwoFactorProviders), len(expected))
	}
	for i, p := range pub.TwoFactorProviders {
		if p != expected[i] {
			t.Errorf("provider[%d]: got %q, want %q", i, p, expected[i])
		}
	}
}

func TestMapCoreErrorPreservesCause(t *testing.T) {
	cause := fmt.Errorf("some cause")
	core := &coreerrors.Error{
		Kind:  coreerrors.KindCrypto,
		Cause: cause,
	}
	mapped := mapCoreError(core)
	if !stderrors.Is(mapped, cause) {
		t.Fatal("mapped error should unwrap to the original cause")
	}
}

func TestMapCoreErrorNoSecretInErrorText(t *testing.T) {
	secret := "SECRET_SHOULD_NOT_APPEAR"
	cause := fmt.Errorf("%s", secret)
	core := &coreerrors.Error{
		Kind:    coreerrors.KindCrypto,
		Message: "decryption error",
		Cause:   cause,
	}
	mapped := mapCoreError(core)
	msg := mapped.Error()
	if strings.Contains(msg, secret) {
		t.Fatalf("mapped Error() must not include cause text; got: %q", msg)
	}
	if !strings.Contains(msg, "decryption error") {
		t.Error("mapped Error() should contain Message")
	}
}

func TestMapCoreErrorAllKinds(t *testing.T) {
	tests := []struct {
		coreKind coreerrors.Kind
		sentinel error
	}{
		{coreerrors.KindUnauthenticated, ErrUnauthorized},
		{coreerrors.KindTwoFactorRequired, ErrTwoFactorRequired},
		{coreerrors.KindLocked, ErrLocked},
		{coreerrors.KindNotFound, ErrNotFound},
		{coreerrors.KindRateLimited, ErrRateLimited},
		{coreerrors.KindCrypto, ErrDecryptionFailed},
		{coreerrors.KindUnsupported, ErrUnsupported},
		{coreerrors.KindPermissionDenied, ErrorKindPermissionDenied},
		{coreerrors.KindConflict, ErrorKindConflict},
		{coreerrors.KindValidation, ErrorKindValidation},
		{coreerrors.KindUnavailable, ErrorKindUnavailable},
		{coreerrors.KindTemporary, ErrorKindTemporary},
		{coreerrors.KindNetwork, ErrorKindNetwork},
	}
	for _, tt := range tests {
		t.Run(string(tt.coreKind), func(t *testing.T) {
			core := &coreerrors.Error{Kind: tt.coreKind}
			mapped := mapCoreError(core)
			if !stderrors.Is(mapped, tt.sentinel) {
				t.Errorf("errors.Is(mapped, sentinel) should be true for kind %q", tt.coreKind)
			}
		})
	}
}

func TestMapCoreErrorNilPublicError(t *testing.T) {
	// Non-core errors should be returned as-is.
	plain := fmt.Errorf("plain error")
	mapped := mapCoreError(plain)
	if !stderrors.Is(mapped, plain) {
		t.Fatal("non-core error should be returned unchanged")
	}
}

func TestMapCoreErrorOpAndCode(t *testing.T) {
	core := &coreerrors.Error{
		Kind:    coreerrors.KindValidation,
		Op:      "ValidateItem",
		Code:    "ERR_BAD_INPUT",
		Message: "name required",
	}
	mapped := mapCoreError(core)
	var pub *Error
	if !stderrors.As(mapped, &pub) {
		t.Fatal("errors.As should succeed")
	}
	if pub.Op != "ValidateItem" {
		t.Fatalf("Op: got %q, want %q", pub.Op, "ValidateItem")
	}
	if pub.Code != "ERR_BAD_INPUT" {
		t.Fatalf("Code: got %q, want %q", pub.Code, "ERR_BAD_INPUT")
	}
	if pub.Message != "name required" {
		t.Fatalf("Message: got %q, want %q", pub.Message, "name required")
	}
}

func TestMapCoreErrorRetryAfterSecondsToDuration(t *testing.T) {
	core := &coreerrors.Error{
		Kind:       coreerrors.KindRateLimited,
		RetryAfter: 60,
	}
	mapped := mapCoreError(core)
	var pub *Error
	if !stderrors.As(mapped, &pub) {
		t.Fatal("errors.As should succeed")
	}
	if pub.RetryAfter != 60*time.Second {
		t.Fatalf("RetryAfter: got %v, want 60s", pub.RetryAfter)
	}
}

// --- TwoFactorError backward compatibility ---

func TestTwoFactorErrorIsTwoFactorRequired(t *testing.T) {
	tfe := &TwoFactorError{
		Providers: []TwoFactorProvider{TwoFactorProviderEmail},
	}
	if !stderrors.Is(tfe, ErrTwoFactorRequired) {
		t.Fatal("TwoFactorError should match ErrTwoFactorRequired")
	}
}

func TestTwoFactorErrorUnwrap(t *testing.T) {
	tfe := &TwoFactorError{
		Providers: []TwoFactorProvider{TwoFactorProviderEmail},
	}
	if !stderrors.Is(stderrors.Unwrap(tfe), ErrTwoFactorRequired) {
		t.Fatal("TwoFactorError.Unwrap() should return ErrTwoFactorRequired")
	}
}

// --- APIError backward compatibility ---

func TestAPIErrorError(t *testing.T) {
	apiErr := &APIError{
		StatusCode: 400,
		Code:       "ERR_BAD_REQUEST",
		Message:    "invalid input",
	}
	msg := apiErr.Error()
	if !strings.Contains(msg, "ERR_BAD_REQUEST") {
		t.Fatalf("APIError.Error() should contain code; got: %q", msg)
	}
}

func TestAPIErrorNil(t *testing.T) {
	var apiErr *APIError
	msg := apiErr.Error()
	if !strings.Contains(msg, "api error") {
		t.Fatalf("nil APIError.Error() should say 'api error'; got: %q", msg)
	}
}
