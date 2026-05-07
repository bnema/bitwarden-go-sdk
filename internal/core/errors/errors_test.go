package errors

import (
	stderrors "errors"
	"fmt"
	"strings"
	"testing"
)

func TestErrorsIsByKind(t *testing.T) {
	err := &Error{Kind: KindRateLimited, RetryAfter: 30}
	if !stderrors.Is(err, &Error{Kind: KindRateLimited}) {
		t.Fatal("expected errors.Is to match by Kind=KindRateLimited")
	}
}

func TestErrorsAsExposesRetryAfter(t *testing.T) {
	err := &Error{Kind: KindRateLimited, RetryAfter: 42}
	var e *Error
	if !stderrors.As(err, &e) {
		t.Fatal("errors.As should succeed")
	}
	if e.RetryAfter != 42 {
		t.Fatalf("RetryAfter: got %d, want 42", e.RetryAfter)
	}
}

func TestErrorDoesNotLeakCauseText(t *testing.T) {
	secret := "SECRET_SHOULD_NOT_APPEAR"
	cause := fmt.Errorf("%s", secret)
	err := &Error{Kind: KindCrypto, Message: "crypto failed", Cause: cause}
	msg := err.Error()
	if strings.Contains(msg, secret) {
		t.Fatalf("Error() must not include cause text; got: %q", msg)
	}
}

func TestIsHelperThroughWrapping(t *testing.T) {
	base := &Error{Kind: KindLocked}
	wrapped := fmt.Errorf("wrap: %w", base)
	if !Is(wrapped, KindLocked) {
		t.Fatal("Is helper should match KindLocked through fmt.Errorf wrapping")
	}
}

func TestErrorIsIgnoresNonErrorTarget(t *testing.T) {
	err := &Error{Kind: KindNotFound}
	if err.Is(nil) {
		t.Fatal("Is(nil) should return false")
	}
	if err.Is(fmt.Errorf("not an *Error")) {
		t.Fatal("Is(non-*Error) should return false")
	}
}

func TestIsHelperNoMatch(t *testing.T) {
	err := &Error{Kind: KindValidation}
	if Is(err, KindNotFound) {
		t.Fatal("Is should return false when Kind does not match")
	}
	if Is(nil, KindNotFound) {
		t.Fatal("Is(nil, ...) should return false")
	}
}

func TestErrorUnwrap(t *testing.T) {
	cause := fmt.Errorf("inner")
	err := &Error{Kind: KindUnknown, Cause: cause}
	unwrapped := stderrors.Unwrap(err)
	if !stderrors.Is(unwrapped, cause) {
		t.Fatal("Unwrap should return Cause")
	}
}

func TestErrorsIsByKindAllKinds(t *testing.T) {
	kinds := []Kind{
		KindUnknown,
		KindUnauthenticated,
		KindPermissionDenied,
		KindNotFound,
		KindConflict,
		KindValidation,
		KindRateLimited,
		KindUnavailable,
		KindTemporary,
		KindNetwork,
		KindTwoFactorRequired,
		KindCrypto,
		KindLocked,
		KindUnsupported,
	}
	for _, k := range kinds {
		err := &Error{Kind: k}
		if !stderrors.Is(err, &Error{Kind: k}) {
			t.Errorf("errors.Is should match Kind=%q", k)
		}
	}
}

func TestErrorSafeDetails(t *testing.T) {
	secret := "DO_NOT_LEAK"
	err := &Error{
		Kind:               KindValidation,
		Op:                 "ValidateItem",
		Status:             422,
		Code:               "ERR_VALIDATION",
		Message:            "invalid field",
		RetryAfter:         15,
		TwoFactorProviders: []string{"email", "totp"},
		Cause:              fmt.Errorf("%s", secret),
	}
	msg := err.Error()
	// Safe fields must appear.
	if !strings.Contains(msg, "op=ValidateItem") {
		t.Error("Error() should contain Op")
	}
	if !strings.Contains(msg, "code=ERR_VALIDATION") {
		t.Error("Error() should contain Code")
	}
	if !strings.Contains(msg, "message=invalid field") {
		t.Error("Error() should contain Message")
	}
	if !strings.Contains(msg, "status=422") {
		t.Error("Error() should contain Status")
	}
	if !strings.Contains(msg, "retry_after=15") {
		t.Error("Error() should contain RetryAfter")
	}
	if !strings.Contains(msg, "providers=email,totp") {
		t.Error("Error() should contain TwoFactorProviders")
	}
	// Cause text must NOT appear.
	if strings.Contains(msg, secret) {
		t.Errorf("Error() must not leak Cause text")
	}
}

func TestZeroValueErrorNonEmpty(t *testing.T) {
	err := &Error{}
	msg := err.Error()
	if msg == "" {
		t.Fatal("zero-value *Error{} should have non-empty Error()")
	}
	// Must at least contain the fixed prefix.
	if !strings.Contains(msg, "bitwarden error") {
		t.Errorf("Error() should contain 'bitwarden error'; got: %q", msg)
	}
}
