// Command sync_search demonstrates Sync then Vault Search/List/Get.
// Set BW_EXAMPLE_LIVE=1 to make actual network calls.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/bnema/bitwarden-go-sdk/bitwarden"
)

func main() {
	if os.Getenv("BW_EXAMPLE_LIVE") != "1" {
		fmt.Println("=== sync_search example (offline) ===")
		fmt.Println("Set BW_EXAMPLE_LIVE=1 to run with real Bitwarden API calls.")
		fmt.Println()
		fmt.Println("This example demonstrates:")
		fmt.Println("  1. client.Sync(ctx)")
		fmt.Println("  2. client.Vault().Search(ctx, query)")
		fmt.Println("  3. client.Vault().List(ctx)")
		fmt.Println("  4. client.Vault().Get(ctx, id)")
		fmt.Println()
		fmt.Println("Requires a logged-in, unlocked client (see login example).")
		return
	}

	ctx := context.Background()

	client, err := bitwarden.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR creating client: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

	// Log in first (see login example for full two-factor handling).
	result, err := client.BeginLogin(ctx, bitwarden.LoginOptions{
		Email:    "REPLACE_ME@example.com",
		Password: "REPLACE_ME",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR BeginLogin: %v\n", err)
		os.Exit(1)
	}
	if result.Challenge != nil {
		// In a real flow you would prompt for the code.
		result, err = client.CompleteLogin(ctx, bitwarden.CompleteLoginOptions{
			Challenge: result.Challenge,
			Provider:  bitwarden.TwoFactorProviderEmail,
			Code:      "REPLACE_ME",
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR CompleteLogin: %v\n", err)
			os.Exit(1)
		}
	}

	// Sync vault from server.
	if err := client.Sync(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Sync: %v\n", err)
		os.Exit(1)
	}

	// List all items.
	all, err := client.Vault().List(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Vault.List: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Vault contains %d items.\n", len(all))

	// Search for items.
	results, err := client.Vault().Search(ctx, "example")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Vault.Search: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Search for 'example' returned %d results.\n", len(results))

	// Get first item by ID if any exist.
	if len(all) > 0 {
		item, err := client.Vault().Get(ctx, all[0].ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR Vault.Get: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("First item: ID=%s Name=%q\n", item.ID, item.Name)
	}
}
