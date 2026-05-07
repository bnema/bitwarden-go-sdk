package secretmem

import "testing"

func TestCloneCopiesAndZeroClears(t *testing.T) {
	original := []byte("secret-data")
	cloned := Clone(original)
	original[0] = 'X'
	if string(cloned) != "secret-data" {
		t.Fatalf("Clone() did not preserve original value: %q", string(cloned))
	}

	alias := cloned
	Zero(cloned)
	for i, b := range alias {
		if b != 0 {
			t.Fatalf("Zero() left byte %d as %d", i, b)
		}
	}
}
