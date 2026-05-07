// Command login demonstrates BeginLogin / CompleteLogin with a two-factor
// challenge flow. Set BW_EXAMPLE_LIVE=1 to make actual network calls.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/bnema/bitwarden-go-sdk/bitwarden"
)

func main() {
	if os.Getenv("BW_EXAMPLE_LIVE") != "1" {
		fmt.Println("=== login example (offline) ===")
		fmt.Println("Set BW_EXAMPLE_LIVE=1 to run with real Bitwarden API calls.")
		fmt.Println()
		fmt.Println("This example demonstrates:")
		fmt.Println("  1. bitwarden.NewClient()")
		fmt.Println("  2. client.BeginLogin(ctx, LoginOptions{Email, Password})")
		fmt.Println("  3. client.CompleteLogin(ctx, CompleteLoginOptions{Challenge, Provider, Code})")
		fmt.Println()
		fmt.Println("Placeholder credentials (REPLACE_ME):")
		fmt.Println("  Email:    REPLACE_ME@example.com")
		fmt.Println("  Password: REPLACE_ME")
		return
	}

	ctx := context.Background()

	client, err := bitwarden.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR creating client: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

	result, err := client.BeginLogin(ctx, bitwarden.LoginOptions{
		Email:    "REPLACE_ME@example.com",
		Password: "REPLACE_ME",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR BeginLogin: %v\n", err)
		os.Exit(1)
	}

	if result.Challenge != nil {
		fmt.Println("Two-factor challenge required. Providers:", result.Challenge.Providers())

		complete, err := client.CompleteLogin(ctx, bitwarden.CompleteLoginOptions{
			Challenge: result.Challenge,
			Provider:  bitwarden.TwoFactorProviderEmail,
			Code:      "REPLACE_ME",
			Remember:  false,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR CompleteLogin: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Login complete. AccountID:", complete.AccountID)
		return
	}

	fmt.Println("Login complete. AccountID:", result.AccountID)
}
