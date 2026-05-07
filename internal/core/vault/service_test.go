package vault

import (
	"testing"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotListReturnsCopies(t *testing.T) {
	items := []Item{
		{ID: "1", Name: "Original"},
	}
	snap := NewSnapshot(items, nil)

	got := snap.List()
	require.Len(t, got, 1)
	assert.Equal(t, "Original", got[0].Name)

	// Mutate the returned slice and its elements.
	got[0].Name = "Mutated"

	// Original snapshot must be unchanged.
	got2 := snap.List()
	assert.Equal(t, "Original", got2[0].Name)
}

func TestSnapshotGetByIDReturnsCopy(t *testing.T) {
	items := []Item{
		{ID: "1", Name: "Original", Notes: "note"},
	}
	snap := NewSnapshot(items, nil)

	got, ok := snap.Get("1")
	require.True(t, ok)
	assert.Equal(t, "Original", got.Name)

	// Mutate returned item.
	got.Name = "Mutated"

	// Original must be unchanged.
	got2, ok := snap.Get("1")
	require.True(t, ok)
	assert.Equal(t, "Original", got2.Name)
}

func TestSnapshotSearchMatchesSafeFields(t *testing.T) {
	items := []Item{
		{
			ID:   "1",
			Name: "My Login",
			Login: &Login{
				Username: "alice",
				Password: "secret123",
				TOTP:     "totpsecret",
				URIs:     []URI{{URI: "https://example.com"}},
			},
		},
		{
			ID:    "2",
			Name:  "Note",
			Notes: "some important note",
		},
		{
			ID:   "3",
			Name: "Work",
			Fields: []Field{
				{Name: "custom", Value: "custom-value"},
			},
		},
	}
	folders := map[string]string{"folder1": "Banking"}
	items = append(items, Item{ID: "4", Name: "Account", FolderID: "folder1"})

	snap := NewSnapshot(items, folders)

	t.Run("match by name", func(t *testing.T) {
		results := snap.Search("Login")
		assert.Len(t, results, 1)
		assert.Equal(t, "1", results[0].ID)
	})

	t.Run("match by username", func(t *testing.T) {
		results := snap.Search("alice")
		assert.Len(t, results, 1)
		assert.Equal(t, "1", results[0].ID)
	})

	t.Run("match by URI", func(t *testing.T) {
		results := snap.Search("example")
		assert.Len(t, results, 1)
		assert.Equal(t, "1", results[0].ID)
	})

	t.Run("match by notes", func(t *testing.T) {
		results := snap.Search("important")
		assert.Len(t, results, 1)
		assert.Equal(t, "2", results[0].ID)
	})

	t.Run("match by custom field name", func(t *testing.T) {
		results := snap.Search("custom")
		assert.Len(t, results, 1)
		assert.Equal(t, "3", results[0].ID)
	})

	t.Run("match by custom field value", func(t *testing.T) {
		results := snap.Search("custom-value")
		assert.Len(t, results, 1)
		assert.Equal(t, "3", results[0].ID)
	})

	t.Run("match by folder name", func(t *testing.T) {
		results := snap.Search("Banking")
		assert.Len(t, results, 1)
		assert.Equal(t, "4", results[0].ID)
	})
}

func TestSnapshotSearchDoesNotIndexPasswordOrTOTP(t *testing.T) {
	items := []Item{
		{
			ID:   "1",
			Name: "Service",
			Login: &Login{
				Password: "super-secret-password",
				TOTP:     "JBSWY3DPEHPK3PXP",
				Username: "user",
			},
		},
	}
	snap := NewSnapshot(items, nil)

	// Searching for password text must NOT match.
	results := snap.Search("super-secret")
	assert.Empty(t, results, "must not match Password")

	// Searching for TOTP must NOT match.
	results = snap.Search("JBSWY3D")
	assert.Empty(t, results, "must not match TOTP")

	// Searching for username should still match.
	results = snap.Search("user")
	assert.Len(t, results, 1)
	assert.Equal(t, "1", results[0].ID)
}

func TestLockedReadsReturnLockedError(t *testing.T) {
	svc := NewService()

	// Simulate locked state.
	svc.locked = true

	_, err := svc.List()
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked), "List should return KindLocked")

	_, _, err = svc.Get("1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked), "Get should return KindLocked")

	_, err = svc.Search("test")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked), "Search should return KindLocked")
}
