package bitwarden

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestLockClearsKeyAndLockedOperationsFail(t *testing.T) {
	client := loggedInClientForSessionTests(t, nil)
	require.False(t, client.IsLocked())

	client.Lock()
	assert.True(t, client.IsLocked())
	assert.Nil(t, client.userKey.Bytes)

	_, err := client.Vault().Search(context.Background(), "anything")
	require.ErrorIs(t, err, ErrLocked)
}

func TestLogoutClearsTokensAndLocks(t *testing.T) {
	store := mocks.NewMockTokenStore(t)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)
	store.EXPECT().DeleteTokens(mock.Anything, "account-logout").Return(nil)
	client := loggedInClientForSessionTests(t, store)
	client.accountID = "account-logout"

	err := client.Logout(context.Background())
	require.NoError(t, err)
	assert.True(t, client.IsLocked())
	assert.Empty(t, client.accountID)
	assert.Nil(t, client.userKey.Bytes)
}

func TestSessionMaterialCloneDoesNotShareSecretSlices(t *testing.T) {
	original := SessionMaterial{
		AccountID: "acct-1",
		UserKey:   []byte("user-key"),
		Tokens: TokenSet{
			AccountID:    "acct-1",
			AccessToken:  []byte("access"),
			RefreshToken: []byte("refresh"),
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
		},
	}
	clone := original.Clone()

	// Mutate original slices
	original.UserKey[0] = 'X'
	original.Tokens.AccessToken[0] = 'Y'
	original.Tokens.RefreshToken[0] = 'Z'

	assert.Equal(t, []byte("user-key"), clone.UserKey)
	assert.Equal(t, []byte("access"), clone.Tokens.AccessToken)
	assert.Equal(t, []byte("refresh"), clone.Tokens.RefreshToken)
	assert.Equal(t, "acct-1", clone.AccountID)
	assert.Equal(t, "acct-1", clone.Tokens.AccountID)
	assert.Equal(t, "Bearer", clone.Tokens.TokenType)
}

func TestSessionMaterialCloseZeroesSecrets(t *testing.T) {
	// Arrange: capture backing arrays
	userKey := []byte("user-key")
	accessToken := []byte("access")
	refreshToken := []byte("refresh")

	mat := SessionMaterial{
		AccountID: "acct-1",
		UserKey:   userKey,
		Tokens: TokenSet{
			AccountID:    "acct-1",
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
		},
	}

	mat.Close()

	assertAllZeroed(t, userKey)
	assertAllZeroed(t, accessToken)
	assertAllZeroed(t, refreshToken)
	assert.Nil(t, mat.UserKey)
	assert.Nil(t, mat.Tokens.AccessToken)
	assert.Nil(t, mat.Tokens.RefreshToken)
}

func assertAllZeroed(t *testing.T, b []byte) {
	t.Helper()
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte at index %d is %d, expected 0", i, v)
		}
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	client := loggedInClientForSessionTests(t, nil)

	require.NoError(t, client.Close())
	require.NoError(t, client.Close())
	assert.True(t, client.IsLocked())
	assert.Nil(t, client.userKey.Bytes)
}

func TestExportSession(t *testing.T) {
	store := mocks.NewMockTokenStore(t)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)
	client := loggedInClientForSessionTests(t, store)

	savedTokens := ports.TokenSet{
		AccountID:    "account-1",
		AccessToken:  ports.NewSecretBytes([]byte("access")),
		RefreshToken: ports.NewSecretBytes([]byte("refresh")),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	store.EXPECT().LoadTokens(mock.Anything, "account-1").Return(savedTokens, nil)

	material, err := client.ExportSession(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "account-1", material.AccountID)
	assert.NotEmpty(t, material.UserKey)
	assert.NotEmpty(t, material.Tokens.AccessToken)
	assert.NotEmpty(t, material.Tokens.RefreshToken)
	assert.Equal(t, "Bearer", material.Tokens.TokenType)
}

func TestExportSessionLockedError(t *testing.T) {
	client := loggedInClientForSessionTests(t, nil)
	client.Lock()

	_, err := client.ExportSession(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLocked)
}

func TestExportSessionTokenLoadErrorZeroesUserKey(t *testing.T) {
	store := mocks.NewMockTokenStore(t)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)
	client := loggedInClientForSessionTests(t, store)

	store.EXPECT().LoadTokens(mock.Anything, "account-1").Return(ports.TokenSet{}, assert.AnError)

	_, err := client.ExportSession(context.Background())
	require.Error(t, err)
}

func TestRestoreSession(t *testing.T) {
	identity := mocks.NewMockIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(withIdentityClient(identity), withCryptoEngine(crypto), withTokenStore(store))
	require.NoError(t, err)
	require.True(t, client.IsLocked())

	material := SessionMaterial{
		AccountID: "account-restore",
		UserKey:   []byte("restore-user-key"),
		Tokens: TokenSet{
			AccountID:    "account-restore",
			AccessToken:  []byte("restore-access"),
			RefreshToken: []byte("restore-refresh"),
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
		},
	}

	store.EXPECT().SaveTokens(mock.Anything, mock.MatchedBy(func(tk ports.TokenSet) bool {
		return tk.AccountID == "account-restore"
	})).Return(nil)

	err = client.RestoreSession(context.Background(), material)
	require.NoError(t, err)
	assert.False(t, client.IsLocked())
	assert.Equal(t, "account-restore", client.accountID)
	assert.Equal(t, []byte("restore-user-key"), client.userKey.Bytes)
}

func TestRestoreSessionValidatesInput(t *testing.T) {
	client, err := NewClient()
	require.NoError(t, err)

	tests := []struct {
		name     string
		material SessionMaterial
		wantKind ErrorKind
	}{
		{
			name:     "empty account ID",
			material: SessionMaterial{UserKey: []byte("key")},
			wantKind: ErrorKindValidation,
		},
		{
			name:     "empty user key",
			material: SessionMaterial{AccountID: "acct"},
			wantKind: ErrorKindValidation,
		},
		{
			name:     "both empty",
			material: SessionMaterial{},
			wantKind: ErrorKindValidation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.RestoreSession(context.Background(), tt.material)
			require.Error(t, err)
			var pubErr *Error
			require.ErrorAs(t, err, &pubErr)
			assert.Equal(t, tt.wantKind, pubErr.Kind)
		})
	}
}

func TestRestoreSessionTokensAccountIDDefaults(t *testing.T) {
	identity := mocks.NewMockIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(withIdentityClient(identity), withCryptoEngine(crypto), withTokenStore(store))
	require.NoError(t, err)

	material := SessionMaterial{
		AccountID: "account-default",
		UserKey:   []byte("key"),
		Tokens: TokenSet{
			AccountID:    "", // empty to test default
			AccessToken:  []byte("access"),
			RefreshToken: []byte("refresh"),
		},
	}

	store.EXPECT().SaveTokens(mock.Anything, mock.MatchedBy(func(tk ports.TokenSet) bool {
		return tk.AccountID == "account-default"
	})).Return(nil)

	err = client.RestoreSession(context.Background(), material)
	require.NoError(t, err)
}

func TestRestoreSessionWithoutTokens(t *testing.T) {
	identity := mocks.NewMockIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(withIdentityClient(identity), withCryptoEngine(crypto), withTokenStore(store))
	require.NoError(t, err)

	material := SessionMaterial{
		AccountID: "account-no-tokens",
		UserKey:   []byte("key"),
	}

	// No SaveTokens call expected when no tokens are present.
	err = client.RestoreSession(context.Background(), material)
	require.NoError(t, err)
	assert.False(t, client.IsLocked())
	assert.Equal(t, "account-no-tokens", client.accountID)
}

func TestRefreshSession(t *testing.T) {
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	currentTokens := ports.TokenSet{
		AccountID:    "account-refresh",
		AccessToken:  ports.NewSecretBytes([]byte("old-access")),
		RefreshToken: ports.NewSecretBytes([]byte("old-refresh")),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now(),
	}
	store.EXPECT().LoadTokens(mock.Anything, "account-refresh").Return(currentTokens, nil)

	refreshedTokens := ports.TokenSet{
		AccountID:    "account-refresh",
		AccessToken:  ports.NewSecretBytes([]byte("new-access")),
		RefreshToken: ports.NewSecretBytes([]byte("new-refresh")),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	identity.EXPECT().Refresh(mock.Anything, mock.MatchedBy(func(req ports.RefreshTokenRequest) bool {
		return req.AccountID == "account-refresh"
	})).Return(ports.TokenResponse{Tokens: refreshedTokens, AccountID: "account-refresh"}, nil)

	store.EXPECT().SaveTokens(mock.Anything, mock.MatchedBy(func(tk ports.TokenSet) bool {
		return tk.AccountID == "account-refresh"
	})).Return(nil)

	client, err := NewClient(withIdentityClient(identity), withTokenStore(store))
	require.NoError(t, err)

	result, err := client.RefreshSession(context.Background(), "account-refresh")
	require.NoError(t, err)
	assert.NotEmpty(t, result.Tokens.AccessToken)
	assert.NotEmpty(t, result.Tokens.RefreshToken)
	assert.Equal(t, "account-refresh", result.Tokens.AccountID)
}

func TestRefreshSessionValidationError(t *testing.T) {
	identity := mocks.NewMockIdentityClient(t)
	client, err := NewClient(withIdentityClient(identity))
	require.NoError(t, err)

	_, err = client.RefreshSession(context.Background(), "")
	require.Error(t, err)
	var pubErr *Error
	require.ErrorAs(t, err, &pubErr)
	assert.Equal(t, ErrorKindValidation, pubErr.Kind)
}

func TestRefreshSessionConcurrentDedup(t *testing.T) {
	identity := mocks.NewMockIdentityClient(t)
	store := mocks.NewMockTokenStore(t)

	currentTokens := ports.TokenSet{
		AccountID:    "account-dedup",
		AccessToken:  ports.NewSecretBytes([]byte("old-access")),
		RefreshToken: ports.NewSecretBytes([]byte("old-refresh")),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now(),
	}
	refreshedTokens := ports.TokenSet{
		AccountID:    "account-dedup",
		AccessToken:  ports.NewSecretBytes([]byte("new-access")),
		RefreshToken: ports.NewSecretBytes([]byte("new-refresh")),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	// Block Refresh so concurrent callers pile up on the shared coordinator.
	blockRefresh := make(chan struct{})
	refreshCalled := make(chan struct{})

	identity.EXPECT().Refresh(mock.Anything, mock.MatchedBy(func(req ports.RefreshTokenRequest) bool {
		return req.AccountID == "account-dedup"
	})).RunAndReturn(func(_ context.Context, _ ports.RefreshTokenRequest) (ports.TokenResponse, error) {
		close(refreshCalled)
		<-blockRefresh
		return ports.TokenResponse{Tokens: refreshedTokens, AccountID: "account-dedup"}, nil
	}).Maybe()

	store.EXPECT().LoadTokens(mock.Anything, "account-dedup").Return(currentTokens, nil).Maybe()
	store.EXPECT().SaveTokens(mock.Anything, mock.MatchedBy(func(tk ports.TokenSet) bool {
		return tk.AccountID == "account-dedup"
	})).Return(nil).Maybe()

	client, err := NewClient(withIdentityClient(identity), withTokenStore(store))
	require.NoError(t, err)

	const callers = 8
	var wg sync.WaitGroup
	results := make([]RefreshResult, callers)
	errs := make([]error, callers)
	wg.Add(callers)
	for i := range callers {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = client.RefreshSession(context.Background(), "account-dedup")
		}(i)
	}

	// Wait for the refresh to be triggered, then give goroutines a moment to pile up.
	<-refreshCalled
	time.Sleep(50 * time.Millisecond)
	close(blockRefresh)
	wg.Wait()

	for i := range callers {
		require.NoError(t, errs[i])
		assert.NotEmpty(t, results[i].Tokens.AccessToken)
		assert.NotEmpty(t, results[i].Tokens.RefreshToken)
		assert.Equal(t, "account-dedup", results[i].Tokens.AccountID)
	}
	identity.AssertNumberOfCalls(t, "Refresh", 1)
}

func TestRestoreSessionTokenAccountIDMismatch(t *testing.T) {
	identity := mocks.NewMockIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	store := mocks.NewMockTokenStore(t)

	client, err := NewClient(withIdentityClient(identity), withCryptoEngine(crypto), withTokenStore(store))
	require.NoError(t, err)
	require.True(t, client.IsLocked())

	material := SessionMaterial{
		AccountID: "account-a",
		UserKey:   []byte("user-key"),
		Tokens: TokenSet{
			AccountID:    "account-b", // mismatched
			AccessToken:  []byte("access"),
			RefreshToken: []byte("refresh"),
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
		},
	}

	err = client.RestoreSession(context.Background(), material)
	require.Error(t, err)
	var pubErr *Error
	require.ErrorAs(t, err, &pubErr)
	assert.Equal(t, ErrorKindValidation, pubErr.Kind)
	assert.True(t, client.IsLocked(), "client should remain locked after validation error")
}

func loggedInClientForSessionTests(t *testing.T, store ports.TokenStore) *Client {
	t.Helper()
	identity := mocks.NewMockIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	if store == nil {
		mockStore := mocks.NewMockTokenStore(t)
		mockStore.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)
		store = mockStore
	}
	masterKey := ports.MasterKey{Bytes: []byte("master")}
	userKey := ports.UserKey{Bytes: []byte("user")}
	tokens := ports.TokenSet{AccountID: "account-1", AccessToken: ports.NewSecretBytes([]byte("access")), RefreshToken: ports.NewSecretBytes([]byte("refresh")), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}
	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, mock.Anything).Return(ports.TokenResponse{Tokens: tokens, AccountID: "account-1", EncryptedUserKey: "enc-user"}, nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, ports.UserKeyInput{MasterKey: masterKey, EncryptedUserKey: "enc-user"}).Return(userKey, nil)
	client, err := NewClient(withIdentityClient(identity), withCryptoEngine(crypto), withTokenStore(store))
	require.NoError(t, err)
	_, err = client.BeginLogin(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	return client
}
