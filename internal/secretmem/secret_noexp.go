//go:build !goexperiment.runtimesecret

package secretmem

// Do runs f directly when runtime/secret is not enabled in the Go toolchain.
func Do(f func()) {
	f()
}
