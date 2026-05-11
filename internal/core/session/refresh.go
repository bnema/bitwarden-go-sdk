package session

import (
	"context"
	stderrors "errors"
	"sync"
	"time"

	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

const defaultRefreshTimeout = 30 * time.Second

// RefreshCoordinator deduplicates concurrent refresh requests per account.
type RefreshCoordinator struct {
	identity ports.IdentityClient
	tokens   ports.TokenStore
	clientID string
	timeout  time.Duration

	mu    sync.Mutex
	calls map[string]*refreshCall
}

// RefreshDependencies groups refresh coordinator dependencies.
type RefreshDependencies struct {
	Identity ports.IdentityClient
	Tokens   ports.TokenStore
	ClientID string
}

// NewRefreshCoordinator constructs a RefreshCoordinator.
func NewRefreshCoordinator(deps RefreshDependencies) *RefreshCoordinator {
	clientID := deps.ClientID
	if clientID == "" {
		clientID = "desktop"
	}
	return &RefreshCoordinator{identity: deps.Identity, tokens: deps.Tokens, clientID: clientID, timeout: defaultRefreshTimeout, calls: map[string]*refreshCall{}}
}

// Refresh loads the account refresh token, refreshes it once for concurrent
// callers, saves successful tokens, and clears stored tokens on invalid grant.
func (c *RefreshCoordinator) Refresh(ctx context.Context, accountID string) (ports.TokenSet, error) {
	if err := ctx.Err(); err != nil {
		return ports.TokenSet{}, err
	}
	if c == nil || c.identity == nil || c.tokens == nil {
		return ports.TokenSet{}, &coreerrors.Error{Kind: coreerrors.KindValidation, Op: "session.Refresh", Code: "missing_dependency", Message: "refresh dependencies are required"}
	}
	if accountID == "" {
		return ports.TokenSet{}, &coreerrors.Error{Kind: coreerrors.KindValidation, Op: "session.Refresh", Code: "missing_account_id", Message: "account ID is required"}
	}

	call, owner := c.getOrCreateCall(accountID)
	if owner {
		refreshCtx, cancel := context.WithTimeout(context.Background(), c.timeout)
		go c.runRefresh(refreshCtx, cancel, accountID, call)
	}

	select {
	case <-ctx.Done():
		return ports.TokenSet{}, ctx.Err()
	case <-call.done:
		return call.tokens.Clone(), call.err
	}
}

func (c *RefreshCoordinator) getOrCreateCall(accountID string) (*refreshCall, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if call := c.calls[accountID]; call != nil {
		return call, false
	}
	call := &refreshCall{done: make(chan struct{})}
	c.calls[accountID] = call
	return call, true
}

func (c *RefreshCoordinator) runRefresh(ctx context.Context, cancel context.CancelFunc, accountID string, call *refreshCall) {
	defer func() {
		cancel()
		c.mu.Lock()
		delete(c.calls, accountID)
		c.mu.Unlock()
		close(call.done)
	}()

	current, err := c.tokens.LoadTokens(ctx, accountID)
	if err != nil {
		call.err = err
		return
	}
	response, err := c.identity.Refresh(ctx, ports.RefreshTokenRequest{AccountID: accountID, ClientID: c.clientID, RefreshToken: current.RefreshToken.Clone()})
	if err != nil {
		if isInvalidGrant(err) {
			// Token deletion is a best-effort side effect. Preserve the
			// original refresh failure so callers can handle invalid_grant.
			_ = c.tokens.DeleteTokens(context.WithoutCancel(ctx), accountID)
		}
		call.err = err
		return
	}
	refreshed := response.Tokens.Clone()
	if refreshed.AccountID == "" {
		refreshed.AccountID = accountID
	}
	if refreshed.RememberedTwoFactorToken.Len() == 0 {
		refreshed.RememberedTwoFactorToken = current.RememberedTwoFactorToken.Clone()
	}
	if err := c.tokens.SaveTokens(ctx, refreshed); err != nil {
		call.err = err
		return
	}
	call.tokens = refreshed
}

func isInvalidGrant(err error) bool {
	var core *coreerrors.Error
	return stderrors.As(err, &core) && core.Kind == coreerrors.KindUnauthenticated && core.Code == "invalid_grant"
}

type refreshCall struct {
	done   chan struct{}
	tokens ports.TokenSet
	err    error
}
