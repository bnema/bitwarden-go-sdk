package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	adaptershttp "github.com/bnema/bitwarden-go-sdk/internal/adapters/http"
	"github.com/bnema/bitwarden-go-sdk/internal/adapters/http/dto"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// BenchmarkSyncDecode measures Sync decode performance with N ciphers.
func BenchmarkSyncDecode(b *testing.B) {
	const n = 100

	// Build a sync response DTO with N ciphers.
	ciphers := make([]dto.CipherDTO, n)
	for i := 0; i < n; i++ {
		notes := "enc-note"
		folderID := "f1"
		ciphers[i] = dto.CipherDTO{
			ID:       "cipher-id",
			Type:     1,
			Name:     "enc-name",
			Notes:    &notes,
			Favorite: false,
			FolderID: &folderID,
			Login: &dto.LoginDTO{
				Username: "enc-user",
				Password: "enc-pass",
				TOTP:     "enc-totp",
				URIs: []dto.LoginURIDTO{
					{
						URI:         "https://example.com",
						Match:       intPtr(0),
						URIChecksum: "enc-checksum",
					},
				},
			},
		}
	}

	resp := dto.SyncResponseDTO{
		Profile: dto.ProfileDTO{
			ID:    "user-id-1",
			Name:  "User",
			Email: "user@example.com",
		},
		Folders: []dto.FolderDTO{
			{ID: "f1", Name: "enc-folder"},
		},
		Ciphers: ciphers,
	}

	body, err := json.Marshal(resp)
	if err != nil {
		b.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sync" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := adaptershttp.NewVaultClient(srv.URL, srv.Client(), nopTokenProvider("bench-token"))
	if err != nil {
		b.Fatalf("NewVaultClient: %v", err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := client.Sync(ctx, ports.SyncOptions{})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func intPtr(v int) *int { return &v }
