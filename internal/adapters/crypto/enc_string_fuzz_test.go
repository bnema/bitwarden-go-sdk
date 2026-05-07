package crypto

import "testing"

// FuzzEncStringParse parses arbitrary strings. When parsing succeeds,
// it serializes the result and re-parses, asserting the type and parts
// are stable.
func FuzzEncStringParse(f *testing.F) {
	// Seed corpus with valid examples from the fixture.
	f.Add("0.AAAAAAAAAAAAAAAAAAAAAA==|AQIDBA==")
	f.Add("2.AAAAAAAAAAAAAAAAAAAAAA==|AQIDBA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	f.Add("7.AQIDBA==")
	// Edge cases.
	f.Add("2.AAAAAAAAAAAAAAAAAAAAAA==|AQIDBA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	f.Add("7.")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		enc, err := ParseEncString(raw)
		if err != nil {
			return // Parsing failure is expected for malformed input.
		}

		// Re-serialize.
		serialized, serErr := enc.String()
		if serErr != nil {
			t.Fatalf("Serialize() failed after successful parse: %v", serErr)
		}

		// Re-parse.
		reparsed, reErr := ParseEncString(serialized)
		if reErr != nil {
			t.Fatalf("Re-parse failed on serialized output %q: %v", serialized, reErr)
		}

		// Type must be stable.
		if enc.Type != reparsed.Type {
			t.Fatalf("type mismatch: original=%d re-parsed=%d", enc.Type, reparsed.Type)
		}

		// Parts must be byte-equal.
		if !byteSliceEq(enc.IV, reparsed.IV) {
			t.Fatalf("IV mismatch after roundtrip")
		}
		if !byteSliceEq(enc.Data, reparsed.Data) {
			t.Fatalf("Data mismatch after roundtrip")
		}
		if !byteSliceEq(enc.MAC, reparsed.MAC) {
			t.Fatalf("MAC mismatch after roundtrip")
		}
	})
}

func byteSliceEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
