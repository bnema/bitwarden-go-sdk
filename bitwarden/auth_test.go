package bitwarden

import (
	"context"
	"testing"
	"time"

	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestBeginLoginReturnsChallengeProviders(t *testing.T) {
	identity, crypto, store := publicAuthDeps(t)
	masterKey := ports.MasterKey{Bytes: []byte("master")}
	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, mock.Anything).Return(ports.TokenResponse{}, twoFactorCoreError("0", "1"))

	client, err := NewClient(WithIdentityClient(identity), WithCryptoEngine(crypto), WithTokenStore(store))
	require.NoError(t, err)
	result, err := client.BeginLogin(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	require.NotNil(t, result.Challenge)
	assert.Equal(t, []TwoFactorProvider{TwoFactorProviderAuthenticator, TwoFactorProviderEmail}, result.Challenge.Providers())
	assert.True(t, client.IsLocked())
}

func TestCompleteLoginUnlocksClient(t *testing.T) {
	identity, crypto, store := publicAuthDeps(t)
	masterKey := ports.MasterKey{Bytes: []byte("master")}
	userKey := ports.UserKey{Bytes: []byte("user")}
	tokens := ports.TokenSet{AccountID: "account-1", AccessToken: ports.NewSecretBytes([]byte("access")), RefreshToken: ports.NewSecretBytes([]byte("refresh")), TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}

	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, mock.Anything).Return(ports.TokenResponse{}, twoFactorCoreError("1"))
	identity.EXPECT().CompleteTwoFactor(mock.Anything, ports.TwoFactorTokenRequest{Email: "alice@example.com", AuthHash: "auth-hash", Provider: ports.TwoFactorProviderEmail, Code: "123456"}).Return(ports.TokenResponse{Tokens: tokens, AccountID: "account-1", EncryptedUserKey: "enc-user"}, nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, ports.UserKeyInput{MasterKey: masterKey, EncryptedUserKey: "enc-user"}).Return(userKey, nil)
	store.EXPECT().SaveTokens(mock.Anything, mock.Anything).Return(nil)

	client, err := NewClient(WithIdentityClient(identity), WithCryptoEngine(crypto), WithTokenStore(store))
	require.NoError(t, err)
	begin, err := client.BeginLogin(context.Background(), LoginOptions{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	complete, err := client.CompleteLogin(context.Background(), CompleteLoginOptions{Challenge: begin.Challenge, Provider: TwoFactorProviderEmail, Code: "123456"})
	require.NoError(t, err)
	assert.Equal(t, "account-1", complete.AccountID)
	assert.False(t, client.IsLocked())
}

func publicAuthDeps(t *testing.T) (*mocks.MockIdentityClient, *mocks.MockCryptoEngine, *mocks.MockTokenStore) {
	t.Helper()
	return mocks.NewMockIdentityClient(t), mocks.NewMockCryptoEngine(t), mocks.NewMockTokenStore(t)
}

func twoFactorCoreError(providers ...string) error {
	return &coreerrors.Error{Kind: coreerrors.KindTwoFactorRequired, Op: "identity.LoginPassword", Code: "two_factor_required", TwoFactorProviders: providers}
}
