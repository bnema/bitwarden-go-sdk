package folders

import (
	"context"
	"testing"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var testUserKey = ports.UserKey{Bytes: []byte("test-user-key-32-bytes-for-testing!")}

func TestFolderListSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	api.EXPECT().
		ListFolders(mock.Anything).
		Return([]ports.EncryptedFolder{
			{ID: "f1", Name: "enc-banking"},
			{ID: "f2", Name: "enc-work"},
		}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(mock.Anything, testUserKey, "enc-banking").
		Return("Banking", nil).
		Once()
	crypto.EXPECT().
		DecryptFolderName(mock.Anything, testUserKey, "enc-work").
		Return("Work", nil).
		Once()

	folders, err := svc.List(context.Background())
	require.NoError(t, err)
	require.Len(t, folders, 2)
	assert.Equal(t, "f1", folders[0].ID)
	assert.Equal(t, "Banking", folders[0].Name)
	assert.Equal(t, "f2", folders[1].ID)
	assert.Equal(t, "Work", folders[1].Name)
}

func TestFolderListLocked(t *testing.T) {
	svc := NewService(Dependencies{Locked: true})

	_, err := svc.List(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked))
}

func TestFolderListAPIFailure(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	api.EXPECT().
		ListFolders(mock.Anything).
		Return(nil, assert.AnError).
		Once()

	_, err := svc.List(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestFolderListDecryptFailure(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	api.EXPECT().
		ListFolders(mock.Anything).
		Return([]ports.EncryptedFolder{{ID: "f1", Name: "enc-bad"}}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(mock.Anything, testUserKey, "enc-bad").
		Return("", assert.AnError).
		Once()

	_, err := svc.List(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestFolderCreateSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, testUserKey, "Banking").
		Return("enc-banking", nil).
		Once()

	api.EXPECT().
		CreateFolder(mock.Anything, ports.EncryptedFolder{Name: "enc-banking"}).
		Return(ports.EncryptedFolder{ID: "f-new", Name: "enc-banking"}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(mock.Anything, testUserKey, "enc-banking").
		Return("Banking", nil).
		Once()

	folder, err := svc.Create(context.Background(), "Banking")
	require.NoError(t, err)
	assert.Equal(t, "f-new", folder.ID)
	assert.Equal(t, "Banking", folder.Name)
}

func TestFolderCreateLocked(t *testing.T) {
	svc := NewService(Dependencies{Locked: true})

	_, err := svc.Create(context.Background(), "Banking")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked))
}

func TestFolderCreateEncryptFailure(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, testUserKey, "Banking").
		Return("", assert.AnError).
		Once()

	_, err := svc.Create(context.Background(), "Banking")
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestFolderCreateAPIFailure(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, testUserKey, "Banking").
		Return("enc-banking", nil).
		Once()

	api.EXPECT().
		CreateFolder(mock.Anything, ports.EncryptedFolder{Name: "enc-banking"}).
		Return(ports.EncryptedFolder{}, assert.AnError).
		Once()

	_, err := svc.Create(context.Background(), "Banking")
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestFolderUpdateSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	crypto.EXPECT().
		EncryptFolderName(mock.Anything, testUserKey, "Renamed").
		Return("enc-renamed", nil).
		Once()

	api.EXPECT().
		UpdateFolder(mock.Anything, "f1", ports.EncryptedFolder{Name: "enc-renamed"}).
		Return(ports.EncryptedFolder{ID: "f1", Name: "enc-renamed"}, nil).
		Once()

	crypto.EXPECT().
		DecryptFolderName(mock.Anything, testUserKey, "enc-renamed").
		Return("Renamed", nil).
		Once()

	folder, err := svc.Update(context.Background(), "f1", "Renamed")
	require.NoError(t, err)
	assert.Equal(t, "f1", folder.ID)
	assert.Equal(t, "Renamed", folder.Name)
}

func TestFolderUpdateLocked(t *testing.T) {
	svc := NewService(Dependencies{Locked: true})

	_, err := svc.Update(context.Background(), "f1", "Renamed")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked))
}

func TestFolderDeleteSuccess(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	api.EXPECT().
		DeleteFolder(mock.Anything, "f1").
		Return(nil).
		Once()

	err := svc.Delete(context.Background(), "f1")
	require.NoError(t, err)
}

func TestFolderDeleteLocked(t *testing.T) {
	svc := NewService(Dependencies{Locked: true})

	err := svc.Delete(context.Background(), "f1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindLocked))
}

func TestFolderDeleteAPIFailure(t *testing.T) {
	api := mocks.NewMockAPIClient(t)
	crypto := mocks.NewMockCryptoEngine(t)

	svc := NewService(Dependencies{
		API:     api,
		Crypto:  crypto,
		UserKey: testUserKey,
		Locked:  false,
	})

	api.EXPECT().
		DeleteFolder(mock.Anything, "f1").
		Return(assert.AnError).
		Once()

	err := svc.Delete(context.Background(), "f1")
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}
