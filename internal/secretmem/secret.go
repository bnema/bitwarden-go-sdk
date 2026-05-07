// Package secretmem centralizes secret byte copying and zeroing.
//
// When built with GOEXPERIMENT=runtimesecret, Do uses the experimental
// runtime/secret package. On linux/amd64 and linux/arm64 this adds runtime
// erasure of temporary registers and stack slots used by Do's call tree. On
// unsupported platforms, and when the experiment is not enabled, Do invokes the
// function directly. In fallback mode, Zero still explicitly overwrites the
// provided buffer, but Do and Clone do not provide runtime erasure guarantees.
package secretmem

// Zero overwrites b with zero bytes under runtime/secret.Do.
func Zero(b []byte) {
	if len(b) == 0 {
		return
	}
	Do(func() {
		for i := range b {
			b[i] = 0
		}
	})
}

// Clone returns a copy of b. The copy operation runs inside Do so registers
// and stack used during the copy are erased when runtime/secret is enabled.
// The returned slice is a regular heap allocation and is not automatically
// erased by the runtime; callers must call Zero when done with it.
func Clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	// Allocate outside Do so writes from inside Do are preserved after runtime
	// secret erasure; callers must later Zero the returned buffer.
	out := make([]byte, len(b))
	Do(func() {
		copy(out, b)
	})
	return out
}
