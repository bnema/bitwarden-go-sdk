//go:build goexperiment.runtimesecret

package secretmem

import "runtime/secret"

// Do runs f inside runtime/secret.Do. With GOEXPERIMENT=runtimesecret,
// runtime/secret currently protects linux/amd64 and linux/arm64 by erasing
// temporary registers, stack slots, and eligible heap allocations created while
// handling secret material. On unsupported platforms runtime/secret.Do invokes
// f directly. It does not protect global variables written by f, goroutines
// spawned by f, or memory reachable through leaked pointers.
func Do(f func()) {
	secret.Do(f)
}
