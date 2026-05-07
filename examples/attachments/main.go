// Command attachments demonstrates Attachments Upload, Metadata, Download,
// and Delete using io.Reader / io.Writer.
// Set BW_EXAMPLE_LIVE=1 to make actual network calls.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/bnema/bitwarden-go-sdk/bitwarden"
)

func main() {
	if os.Getenv("BW_EXAMPLE_LIVE") != "1" {
		fmt.Println("=== attachments example (offline) ===")
		fmt.Println("Set BW_EXAMPLE_LIVE=1 to run with real Bitwarden API calls.")
		fmt.Println()
		fmt.Println("This example demonstrates:")
		fmt.Println("  1. client.Attachments().Upload(ctx, opts)")
		fmt.Println("  2. client.Attachments().Metadata(ctx, cipherID, attachmentID)")
		fmt.Println("  3. client.Attachments().Download(ctx, cipherID, attachmentID, dst)")
		fmt.Println("  4. client.Attachments().Delete(ctx, cipherID, attachmentID)")
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

	const cipherID = "REPLACE_ME_CIPHER_ID"
	const fileName = "example.txt"
	content := "Hello, Bitwarden!"
	reader := strings.NewReader(content)

	// Upload an attachment.
	att, err := client.Attachments().Upload(ctx, bitwarden.AttachmentUploadOptions{
		ItemID:   cipherID,
		FileName: fileName,
		Size:     int64(len(content)),
		Reader:   reader,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Attachments.Upload: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Uploaded attachment ID=%s FileName=%q\n", att.ID, att.FileName)

	// Get attachment metadata.
	meta, err := client.Attachments().Metadata(ctx, cipherID, att.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Attachments.Metadata: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Metadata: ID=%s FileName=%q Size=%d\n", meta.ID, meta.FileName, meta.Size)

	// Download the attachment.
	var buf bytes.Buffer
	if err := client.Attachments().Download(ctx, cipherID, att.ID, &buf); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Attachments.Download: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Downloaded content: %q\n", buf.String())

	// Delete the attachment.
	if err := client.Attachments().Delete(ctx, cipherID, att.ID); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR Attachments.Delete: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Attachment deleted.")
}
