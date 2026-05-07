//go:build goexperiment.runtimesecret

package secretmem

import (
	"runtime/secret"
	"testing"
)

func TestDoEnablesRuntimeSecret(t *testing.T) {
	Do(func() {
		if !secret.Enabled() {
			t.Fatal("runtime/secret must be enabled inside secretmem.Do")
		}
	})
}
