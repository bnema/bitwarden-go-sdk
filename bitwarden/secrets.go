package bitwarden

import (
	stderrors "errors"
)

const secretRedactedText = "[REDACTED]"

// Secret holds sensitive data in an owned byte buffer.
// String, GoString, and MarshalJSON all prevent accidental exposure.
// Use Reveal() to obtain a RevealedSecret for safe, transient access.
type Secret struct {
	buf []byte
}

// NewSecretString creates a Secret holding a copy of value.
func NewSecretString(value string) *Secret {
	return NewSecretBytes([]byte(value))
}

// NewSecretBytes creates a Secret holding a copy of value.
func NewSecretBytes(value []byte) *Secret {
	buf := make([]byte, len(value))
	copy(buf, value)
	return &Secret{buf: buf}
}

// String returns a constant redacted text. It never includes plaintext.
func (s *Secret) String() string {
	return secretRedactedText
}

// GoString returns a constant redacted text for %#v formatting.
func (s *Secret) GoString() string {
	return secretRedactedText
}

// MarshalJSON returns an error to prevent accidental JSON serialization
// of secret material. It never includes plaintext in the returned data.
func (s *Secret) MarshalJSON() ([]byte, error) {
	return nil, stderrors.New("bitwarden: Secret cannot be marshalled to JSON")
}

// Reveal returns a RevealedSecret containing a copy of the owned buffer.
// It is the caller's responsibility to call Close() on the returned value.
func (s *Secret) Reveal() (*RevealedSecret, error) {
	if s.buf == nil {
		return nil, stderrors.New("bitwarden: Secret has been closed")
	}
	buf := make([]byte, len(s.buf))
	copy(buf, s.buf)
	return &RevealedSecret{buf: buf}, nil
}

// Close clears the owned byte buffer. It is idempotent.
func (s *Secret) Close() error {
	s.buf = nil
	return nil
}

// RevealedSecret holds a transient copy of secret material.
// Call Close() when the plaintext is no longer needed.
type RevealedSecret struct {
	buf []byte
}

// Bytes returns the plaintext bytes. If the revealed secret has been
// closed, it returns nil.
func (r *RevealedSecret) Bytes() []byte {
	return r.buf
}

// String returns the plaintext as a string.
func (r *RevealedSecret) String() string {
	return string(r.buf)
}

// Close clears the revealed copy. It is idempotent.
func (r *RevealedSecret) Close() error {
	r.buf = nil
	return nil
}
