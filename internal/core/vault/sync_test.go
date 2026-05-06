package vault

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	mocks "github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ctxb() context.Context {
	return context.Background()
}

func TestSyncBuildsDecryptedSnapshot(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}

	api.EXPECT().
		Sync(ctxb(), ports.SyncOptions{}).
		Return(ports.SyncResult{
			Folders: []ports.EncryptedFolder{
				{ID: "f1", Name: "enc-banking"},
			},
			Ciphers: []ports.EncryptedCipher{
				{ID: "c1", Type: 1, Name: "enc-login-name", FolderID: "f1"},
			},
		}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(ctxb(), key, "enc-banking").
		Return("Banking", nil).
		Once()

	crypto.EXPECT().
		DecryptCipher(ctxb(), key, ports.EncryptedCipher{ID: "c1", Type: 1, Name: "enc-login-name", FolderID: "f1"}).
		Return(ports.Cipher{ID: "c1", Type: 1, Name: "My Login", FolderID: "f1"}, nil).
		Once()

	svc.SetUserKey(key)
	err := svc.Sync(context.Background())
	require.NoError(t, err)

	// List returns decrypted data.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "c1", items[0].ID)
	assert.Equal(t, "My Login", items[0].Name)

	// Get by ID.
	item, ok, err := svc.Get("c1")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "My Login", item.Name)

	// Search by name.
	results, err := svc.Search("Login")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "c1", results[0].ID)

	// Search by folder name.
	results, err = svc.Search("Banking")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "c1", results[0].ID)

	// Search non-existent.
	results, err = svc.Search("nonexistent")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestSyncReplacesSnapshotAtomically(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	// Start with an existing snapshot.
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})
	svc.snapshot = NewSnapshot(
		[]Item{{ID: "existing", Name: "Existing Item"}},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	api.EXPECT().
		Sync(ctxb(), ports.SyncOptions{}).
		Return(ports.SyncResult{
			Folders: []ports.EncryptedFolder{
				{ID: "f1", Name: "enc-banking"},
			},
			Ciphers: []ports.EncryptedCipher{
				{ID: "c1", Type: 1, Name: "enc-good"},
				{ID: "c2", Type: 1, Name: "enc-bad"},
			},
		}, nil).
		Once()

	// Folder decrypt succeeds.
	crypto.EXPECT().
		DecryptFolderName(ctxb(), key, "enc-banking").
		Return("Banking", nil).
		Once()

	// First cipher decrypt succeeds.
	crypto.EXPECT().
		DecryptCipher(ctxb(), key, ports.EncryptedCipher{ID: "c1", Type: 1, Name: "enc-good"}).
		Return(ports.Cipher{ID: "c1", Type: 1, Name: "Good Item"}, nil).
		Once()

	// Second cipher decrypt fails.
	crypto.EXPECT().
		DecryptCipher(ctxb(), key, ports.EncryptedCipher{ID: "c2", Type: 1, Name: "enc-bad"}).
		Return(ports.Cipher{}, assert.AnError).
		Once()

	err := svc.Sync(context.Background())
	require.Error(t, err)

	// Existing snapshot must be preserved.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "existing", items[0].ID)
	assert.Equal(t, "Existing Item", items[0].Name)
}

func TestSyncSkipsOrganizationCiphers(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	orgID := "org-1"
	api.EXPECT().
		Sync(ctxb(), ports.SyncOptions{}).
		Return(ports.SyncResult{
			Ciphers: []ports.EncryptedCipher{
				{ID: "personal", Type: 1, Name: "enc-personal"},
				{ID: "org", Type: 1, Name: "enc-org", OrganizationID: orgID, Key: "enc-org-key"},
			},
		}, nil).
		Once()

	crypto.EXPECT().
		DecryptCipher(ctxb(), key, ports.EncryptedCipher{ID: "personal", Type: 1, Name: "enc-personal"}).
		Return(ports.Cipher{ID: "personal", Type: 1, Name: "Personal Item"}, nil).
		Once()

	err := svc.Sync(context.Background())
	require.NoError(t, err)

	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "personal", items[0].ID)
}

func TestSyncContextCancellation(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	// Start with an existing snapshot.
	svc.snapshot = NewSnapshot(
		[]Item{{ID: "existing", Name: "Existing Item"}},
		nil,
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Immediately canceled.

	err := svc.Sync(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)

	// Existing snapshot must be preserved.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "existing", items[0].ID)
}

func TestSyncLockedReturnsLocked(t *testing.T) {
	t.Parallel()

	svc := NewService(Dependencies{
		Locked: true,
	})

	// Also explicitly lock via SetLocked to be sure.
	svc.SetLocked(true)

	err := svc.Sync(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked), "expected KindLocked, got %v", err)
}

func TestSyncDoesNotReplaceSnapshotIfLockedDuringDecrypt(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	svc := NewService(Dependencies{
		API:    api,
		Crypto: crypto,
		Locked: false,
	})

	// Start with an existing snapshot item.
	svc.snapshot = NewSnapshot(
		[]Item{{ID: "existing", Name: "Existing Item"}},
		nil,
	)

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	// API.Sync returns one encrypted cipher.
	api.EXPECT().
		Sync(ctxb(), ports.SyncOptions{}).
		Return(ports.SyncResult{
			Ciphers: []ports.EncryptedCipher{
				{ID: "c1", Type: 1, Name: "enc-new-item"},
			},
		}, nil).
		Once()

	// Channel to block DecryptCipher until we lock the vault.
	decryptStarted := make(chan struct{})
	unblockDecrypt := make(chan struct{})

	crypto.EXPECT().
		DecryptCipher(ctxb(), key, ports.EncryptedCipher{ID: "c1", Type: 1, Name: "enc-new-item"}).
		RunAndReturn(func(_ context.Context, _ ports.UserKey, _ ports.EncryptedCipher) (ports.Cipher, error) {
			close(decryptStarted)
			<-unblockDecrypt
			return ports.Cipher{ID: "c1", Type: 1, Name: "New Item"}, nil
		}).
		Once()

	// Start Sync in a goroutine.
	var syncErr error
	syncDone := make(chan struct{})
	go func() {
		syncErr = svc.Sync(context.Background())
		close(syncDone)
	}()

	// Wait for decrypt to start, then lock the vault.
	<-decryptStarted
	svc.SetLocked(true)

	// Unblock the decrypt.
	close(unblockDecrypt)

	// Wait for Sync to finish.
	<-syncDone

	// Sync must return KindLocked.
	require.Error(t, syncErr)
	assert.True(t, errors.Is(syncErr, errors.KindLocked), "expected KindLocked, got %v", syncErr)

	// Unlock to verify snapshot state.
	svc.SetLocked(false)

	// List must NOT contain the newly decrypted item.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "existing", items[0].ID)
	assert.Equal(t, "Existing Item", items[0].Name)
}

func TestSyncUsesBoundedDecryptWorkers(t *testing.T) {
	t.Parallel()

	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	const numCiphers = 20
	const maxWorkers = 4

	svc := NewService(Dependencies{
		API:            api,
		Crypto:         crypto,
		Locked:         false,
		DecryptWorkers: maxWorkers,
	})

	key := ports.UserKey{Bytes: []byte("test-key-64-bytes-for-user-key-here-12345678")}
	svc.SetUserKey(key)

	encCiphers := make([]ports.EncryptedCipher, numCiphers)
	for i := 0; i < numCiphers; i++ {
		encCiphers[i] = ports.EncryptedCipher{
			ID:   "c",
			Type: 1,
			Name: "enc",
		}
	}

	api.EXPECT().
		Sync(ctxb(), ports.SyncOptions{}).
		Return(ports.SyncResult{Ciphers: encCiphers}, nil).
		Once()

	// Track concurrency with an atomic counter.
	var concurrent int64
	var maxConcurrent int64

	crypto.EXPECT().
		DecryptCipher(ctxb(), key, ports.EncryptedCipher{ID: "c", Type: 1, Name: "enc"}).
		RunAndReturn(func(_ context.Context, _ ports.UserKey, ec ports.EncryptedCipher) (ports.Cipher, error) {
			v := atomic.AddInt64(&concurrent, 1)
			// Track peak concurrency.
			for {
				cur := atomic.LoadInt64(&maxConcurrent)
				if v <= cur || atomic.CompareAndSwapInt64(&maxConcurrent, cur, v) {
					break
				}
			}
			// Simulate some work.
			// Decrement when done.
			defer atomic.AddInt64(&concurrent, -1)
			return ports.Cipher{
				ID:   ec.ID,
				Type: ec.Type,
				Name: "decrypted-" + ec.ID,
			}, nil
		}).
		Times(numCiphers)

	err := svc.Sync(context.Background())
	require.NoError(t, err)

	// Assert that max concurrency never exceeded the worker limit.
	assert.LessOrEqual(t, maxConcurrent, int64(maxWorkers),
		"max concurrent decrypts must not exceed configured workers")

	// Verify items were decrypted.
	items, err := svc.List()
	require.NoError(t, err)
	require.Len(t, items, numCiphers)
}
