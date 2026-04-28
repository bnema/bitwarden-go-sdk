// Command items demonstrates Vault Create, Update, Trash, Restore, Delete.
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
		fmt.Println("=== items example (offline) ===")
		fmt.Println("Set BW_EXAMPLE_LIVE=1 to run with real Bitwarden API calls.")
		fmt.Println()
		fmt.Println("This example demonstrates:")
		fmt.Println("  1. client.Vault().Create(ctx, item)")
		fmt.Println("  2. client.Vault().Update(ctx, id, item)")
		fmt.Println("  3. client.Vault().Trash(ctx, id)")
		fmt.Println("  4. client.Vault().Restore(ctx, id)")
		fmt.Println("  5. client.Vault().Delete(ctx, id)")
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

	// Log in first.
	result, err := client.BeginLogin(ctx, bitwarden.LoginOptions{
		Email:    "REPLACE_ME@example.com",
		Password: "REPLACE_ME",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR BeginLogin: %v\n", err)
		os.Exit(1)
	}
	if result.Challenge != nil {
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

	// Sync first.
	if err := client.Sync(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Sync: %v\n", err)
		os.Exit(1)
	}

	// Create a new login item.
	created, err := client.Vault().Create(ctx, bitwarden.Item{
		Type:     bitwarden.ItemTypeLogin,
		Name:     "Example Login",
		Username: "user",
		URI:      "https://example.com",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Vault.Create: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created item ID=%s Name=%q\n", created.ID, created.Name)

	// Update the item name.
	updated, err := client.Vault().Update(ctx, created.ID, bitwarden.Item{
		Type:     bitwarden.ItemTypeLogin,
		Name:     "Updated Example Login",
		Username: "user",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Vault.Update: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Updated item ID=%s Name=%q\n", updated.ID, updated.Name)

	// Trash the item.
	if err := client.Vault().Trash(ctx, created.ID); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Vault.Trash: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Trashed item.")

	// Restore the item.
	restored, err := client.Vault().Restore(ctx, created.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Vault.Restore: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Restored item ID=%s Name=%q\n", restored.ID, restored.Name)

	// Delete the item permanently.
	if err := client.Vault().Delete(ctx, created.ID); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Vault.Delete: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Deleted item permanently.")
}
