// Command tokenstore documents the SDK's token-storage policy.
//
// v0.1.0 keeps OAuth session tokens in an internal in-memory store. The store
// zeroises replaced and deleted token bytes, and the SDK does not persist tokens
// to disk. Applications that need disk persistence should add it outside the SDK
// boundary, for example by creating a new client and logging in again after
// unlocking an application-managed keychain.
package main

import (
	"fmt"
	"os"

	"github.com/bnema/bitwarden-go-sdk/bitwarden"
)

func main() {
	if os.Getenv("BW_EXAMPLE_LIVE") != "1" {
		fmt.Println("=== token storage policy example (offline) ===")
		fmt.Println()
		fmt.Println("The SDK uses an internal in-memory token store by default.")
		fmt.Println("No token bytes are written to disk by the SDK.")
		fmt.Println("Handle any persistence at your application boundary.")
		return
	}

	client, err := bitwarden.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR creating client: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

	fmt.Println("Client created with the default in-memory token store.")
}
