package bitwarden

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// --- Redaction via fmt verbs ---

func TestSecretStringRedacts(t *testing.T) {
	secret := NewSecretString("my-s3cret-value")
	out := secret.String()
	if out == "my-s3cret-value" {
		t.Fatalf("String() must not expose plaintext; got: %q", out)
	}
	if strings.Contains(out, "my-s3cret-value") {
		t.Fatalf("String() must not include plaintext; got: %q", out)
	}
}

func TestSecretGoStringRedacts(t *testing.T) {
	secret := NewSecretString("my-s3cret-value")
	out := fmt.Sprintf("%#v", secret)
	if out == "my-s3cret-value" {
		t.Fatalf("GoString() must not expose plaintext; got: %q", out)
	}
	if strings.Contains(out, "my-s3cret-value") {
		t.Fatalf("GoString() must not include plaintext; got: %q", out)
	}
}

// --- JSON marshal returns an error, never plaintext ---

func TestSecretMarshalJSONReturnsError(t *testing.T) {
	secret := NewSecretString("my-s3cret-value")
	data, err := json.Marshal(secret)
	if err == nil {
		t.Fatalf("json.Marshal must return an error; got data: %q", string(data))
	}
	if len(data) != 0 {
		t.Fatalf("json.Marshal must return nil/empty bytes on error; got: %q", string(data))
	}
	if strings.Contains(string(data), "my-s3cret-value") {
		t.Fatal("json.Marshal must not include plaintext in returned bytes")
	}
	if strings.Contains(err.Error(), "my-s3cret-value") {
		t.Fatal("json.Marshal error must not include plaintext")
	}
}

// --- Reveal returns the plaintext ---

func TestSecretRevealString(t *testing.T) {
	secret := NewSecretString("my-s3cret-string")
	revealed, err := secret.Reveal()
	if err != nil {
		t.Fatalf("Reveal() returned error: %v", err)
	}
	if revealed == nil {
		t.Fatal("Reveal() returned nil revealed secret")
	}
	if revealed.String() != "my-s3cret-string" {
		t.Fatalf("RevealedSecret.String(): got %q, want %q", revealed.String(), "my-s3cret-string")
	}
}

func TestSecretRevealBytes(t *testing.T) {
	original := []byte("byte-secret-data")
	secret := NewSecretBytes(original)
	revealed, err := secret.Reveal()
	if err != nil {
		t.Fatalf("Reveal() returned error: %v", err)
	}
	if string(revealed.Bytes()) != string(original) {
		t.Fatalf("RevealedSecret.Bytes(): got %q, want %q", string(revealed.Bytes()), string(original))
	}
}

// --- NewSecretBytes copies input ---

func TestNewSecretBytesCopiesInput(t *testing.T) {
	original := []byte("original-secret")
	secret := NewSecretBytes(original)
	// Mutate the original slice.
	original[0] = 'X'
	revealed, err := secret.Reveal()
	if err != nil {
		t.Fatalf("Reveal() returned error: %v", err)
	}
	if string(revealed.Bytes()) == "Xriginal-secret" {
		t.Fatal("NewSecretBytes must copy the input; Reveal() returned mutated data")
	}
	if string(revealed.Bytes()) != "original-secret" {
		t.Fatalf("NewSecretBytes copy mismatch: got %q, want %q", string(revealed.Bytes()), "original-secret")
	}
}

// --- RevealedSecret.Close clears the revealed copy ---

func TestRevealedSecretCloseClearsCopy(t *testing.T) {
	secret := NewSecretString("close-me-please")
	revealed, err := secret.Reveal()
	if err != nil {
		t.Fatalf("Reveal() returned error: %v", err)
	}
	if err := revealed.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
	// After close, Bytes should not return plaintext.
	if bytes := revealed.Bytes(); bytes != nil {
		t.Fatalf("RevealedSecret.Bytes() after Close should return nil; got: %q", string(bytes))
	}
	// After close, String should not return plaintext.
	if s := revealed.String(); s == "close-me-please" {
		t.Fatal("RevealedSecret.String() after Close must not expose plaintext")
	}
}

func TestRevealedSecretCloseIsIdempotent(t *testing.T) {
	secret := NewSecretString("idempotent-close")
	revealed, err := secret.Reveal()
	if err != nil {
		t.Fatalf("Reveal() returned error: %v", err)
	}
	if err := revealed.Close(); err != nil {
		t.Fatalf("first Close() returned error: %v", err)
	}
	if err := revealed.Close(); err != nil {
		t.Fatalf("second Close() returned error: %v", err)
	}
}

// --- Secret.Close clears the owned buffer ---

func TestSecretCloseClearsOwnedBuffer(t *testing.T) {
	secret := NewSecretString("owner-buffer-secret")
	if err := secret.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
	// In-package access: inspect the unexported buffer.
	if secret.buf != nil {
		t.Fatalf("Secret.buf after Close should be nil; got: %q", string(secret.buf))
	}
}

func TestSecretCloseIsIdempotent(t *testing.T) {
	secret := NewSecretString("idempotent-buffer")
	if err := secret.Close(); err != nil {
		t.Fatalf("first Close() returned error: %v", err)
	}
	if err := secret.Close(); err != nil {
		t.Fatalf("second Close() returned error: %v", err)
	}
}

// --- Reveal after Secret.Close ---

func TestSecretRevealAfterCloseReturnsError(t *testing.T) {
	secret := NewSecretString("reveal-after-close")
	if err := secret.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
	revealed, err := secret.Reveal()
	if err == nil {
		t.Fatalf("Reveal() after Close should return an error; got: %v", revealed)
	}
}
