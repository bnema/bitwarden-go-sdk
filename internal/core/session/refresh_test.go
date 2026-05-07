package session

import (
	"context"
	"sync"
	"testing"
	"time"

	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshConcurrentCallersShareOneRemoteRequest(t *testing.T) {
	block := make(chan struct{})
	identity := &refreshIdentityStub{tokens: tokenSet("account-1", "new-refresh"), block: block}
	store := newRefreshStore(tokenSet("account-1", "old-refresh"))
	coord := NewRefreshCoordinator(RefreshDependencies{Identity: identity, Tokens: store})

	const callers = 16
	var wg sync.WaitGroup
	wg.Add(callers)
	results := make([]ports.TokenSet, callers)
	errs := make([]error, callers)
	for i := range callers {
		go func() {
			defer wg.Done()
			results[i], errs[i] = coord.Refresh(context.Background(), "account-1")
		}()
	}
	require.Eventually(t, func() bool { return identity.callCount() == 1 }, time.Second, time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	close(block)
	wg.Wait()

	for i := range callers {
		require.NoError(t, errs[i])
		assert.Equal(t, "new-refresh", string(results[i].RefreshToken.Bytes()))
	}
	assert.Equal(t, 1, identity.callCount())
	assert.Equal(t, 1, store.saves)
}

func TestRefreshFailureFansOut(t *testing.T) {
	wantErr := &coreerrors.Error{Kind: coreerrors.KindUnavailable, Op: "identity.Refresh"}
	identity := &refreshIdentityStub{err: wantErr, block: make(chan struct{})}
	store := newRefreshStore(tokenSet("account-1", "old-refresh"))
	coord := NewRefreshCoordinator(RefreshDependencies{Identity: identity, Tokens: store})

	const callers = 4
	var wg sync.WaitGroup
	wg.Add(callers)
	errs := make([]error, callers)
	for i := range callers {
		go func() {
			defer wg.Done()
			_, errs[i] = coord.Refresh(context.Background(), "account-1")
		}()
	}
	require.Eventually(t, func() bool { return identity.callCount() == 1 }, time.Second, time.Millisecond)
	close(identity.block)
	wg.Wait()

	for i := range callers {
		require.ErrorIs(t, errs[i], wantErr)
	}
	assert.Equal(t, 1, identity.callCount())
}

func TestRefreshInvalidGrantClearsTokens(t *testing.T) {
	identityErr := &coreerrors.Error{Kind: coreerrors.KindUnauthenticated, Code: "invalid_grant"}
	identity := &refreshIdentityStub{err: identityErr}
	store := newRefreshStore(tokenSet("account-1", "old-refresh"))
	coord := NewRefreshCoordinator(RefreshDependencies{Identity: identity, Tokens: store})

	_, err := coord.Refresh(context.Background(), "account-1")
	require.ErrorIs(t, err, identityErr)
	assert.True(t, coreerrors.Is(err, coreerrors.KindUnauthenticated))
	assert.Equal(t, 1, store.deletes)
}

func TestRefreshInvalidGrantPreservesRefreshErrorWhenDeleteFails(t *testing.T) {
	identityErr := &coreerrors.Error{Kind: coreerrors.KindUnauthenticated, Code: "invalid_grant"}
	identity := &refreshIdentityStub{err: identityErr}
	store := newRefreshStore(tokenSet("account-1", "old-refresh"))
	store.deleteErr = &coreerrors.Error{Kind: coreerrors.KindUnavailable, Op: "tokens.DeleteTokens"}
	coord := NewRefreshCoordinator(RefreshDependencies{Identity: identity, Tokens: store})

	_, err := coord.Refresh(context.Background(), "account-1")
	require.ErrorIs(t, err, identityErr)
	assert.True(t, coreerrors.Is(err, coreerrors.KindUnauthenticated))
	assert.Equal(t, 1, store.deletes)
}

func TestRefreshUsesConfiguredClientID(t *testing.T) {
	identity := &refreshIdentityStub{tokens: tokenSet("account-1", "new-refresh")}
	store := newRefreshStore(tokenSet("account-1", "old-refresh"))
	coord := NewRefreshCoordinator(RefreshDependencies{Identity: identity, Tokens: store, ClientID: "sdk-go"})

	_, err := coord.Refresh(context.Background(), "account-1")
	require.NoError(t, err)
	assert.Equal(t, "sdk-go", identity.clientID())
}

func TestRefreshContextCancellationDoesNotLeakCall(t *testing.T) {
	block := make(chan struct{})
	identity := &refreshIdentityStub{tokens: tokenSet("account-1", "new-refresh"), block: block}
	store := newRefreshStore(tokenSet("account-1", "old-refresh"))
	coord := NewRefreshCoordinator(RefreshDependencies{Identity: identity, Tokens: store})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := coord.Refresh(ctx, "account-1")
		done <- err
	}()
	require.Eventually(t, func() bool { return identity.callCount() == 1 }, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	close(block)
	require.Eventually(t, func() bool { return coord.inflightCount() == 0 }, time.Second, time.Millisecond)
}

func TestRefreshRemoteTimeoutCleansInflight(t *testing.T) {
	identity := &refreshIdentityStub{tokens: tokenSet("account-1", "new-refresh"), block: make(chan struct{})}
	store := newRefreshStore(tokenSet("account-1", "old-refresh"))
	coord := NewRefreshCoordinator(RefreshDependencies{Identity: identity, Tokens: store})
	coord.timeout = time.Millisecond

	_, err := coord.Refresh(context.Background(), "account-1")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Eventually(t, func() bool { return coord.inflightCount() == 0 }, time.Second, time.Millisecond)
}

type refreshIdentityStub struct {
	mu           sync.Mutex
	calls        int
	lastClientID string
	tokens       ports.TokenSet
	err          error
	block        chan struct{}
}

func (s *refreshIdentityStub) Prelogin(context.Context, string) (ports.PreloginResult, error) {
	panic("not used")
}

func (s *refreshIdentityStub) LoginPassword(context.Context, ports.PasswordTokenRequest) (ports.TokenResponse, error) {
	panic("not used")
}

func (s *refreshIdentityStub) CompleteTwoFactor(context.Context, ports.TwoFactorTokenRequest) (ports.TokenResponse, error) {
	panic("not used")
}

func (s *refreshIdentityStub) Refresh(ctx context.Context, req ports.RefreshTokenRequest) (ports.TokenResponse, error) {
	s.mu.Lock()
	s.calls++
	s.lastClientID = req.ClientID
	s.mu.Unlock()
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return ports.TokenResponse{}, ctx.Err()
		}
	}
	return ports.TokenResponse{Tokens: s.tokens}, s.err
}

func (s *refreshIdentityStub) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *refreshIdentityStub) clientID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastClientID
}

type refreshStoreStub struct {
	mu        sync.Mutex
	tokens    ports.TokenSet
	saves     int
	deletes   int
	deleteErr error
}

func newRefreshStore(tokens ports.TokenSet) *refreshStoreStub {
	return &refreshStoreStub{tokens: tokens}
}

func (s *refreshStoreStub) LoadTokens(context.Context, string) (ports.TokenSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens.Clone(), nil
}

func (s *refreshStoreStub) SaveTokens(_ context.Context, tokens ports.TokenSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	s.tokens = tokens.Clone()
	return nil
}

func (s *refreshStoreStub) DeleteTokens(context.Context, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.tokens.Close()
	return nil
}

func (c *RefreshCoordinator) inflightCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

func tokenSet(accountID, refresh string) ports.TokenSet {
	return ports.TokenSet{AccountID: accountID, AccessToken: ports.NewSecretBytes([]byte("access")), RefreshToken: ports.NewSecretBytes([]byte(refresh)), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}
}
