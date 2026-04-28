package auth

import (
	"context"
	"testing"
	"time"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/ports/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestBeginLoginWithoutTwoFactorSavesTokensAndUnlocksUserKey(t *testing.T) {
	svc, identity, crypto, store := newTestService(t)
	masterKey := ports.MasterKey{Bytes: []byte("master-key")}
	userKey := ports.UserKey{Bytes: []byte("user-key")}
	tokens := tokenSet("account-1")

	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, ports.MasterKeyInput{Email: "alice@example.com", Password: "password", KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, ports.AuthHashInput{Password: "password", MasterKey: masterKey}).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, ports.PasswordTokenRequest{Email: "alice@example.com", AuthHash: "auth-hash"}).Return(ports.TokenResponse{Tokens: tokens, AccountID: "account-1", EncryptedUserKey: "enc-user-key"}, nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, ports.UserKeyInput{MasterKey: masterKey, EncryptedUserKey: "enc-user-key"}).Return(userKey, nil)
	store.EXPECT().SaveTokens(mock.Anything, mock.MatchedBy(func(got ports.TokenSet) bool { return got.AccountID == "account-1" })).Return(nil)

	result, err := svc.BeginLogin(context.Background(), LoginInput{Email: " Alice@Example.COM ", Password: "password"})
	require.NoError(t, err)
	require.NotNil(t, result.Login)
	assert.Nil(t, result.Challenge)
	assert.Equal(t, "account-1", result.Login.AccountID)
	assert.Equal(t, userKey.Bytes, result.Login.UserKey.Bytes)
}

func TestBeginLoginReturnsTwoFactorChallenge(t *testing.T) {
	svc, identity, crypto, _ := newTestService(t)
	masterKey := ports.MasterKey{Bytes: []byte("master-key")}

	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, ports.AuthHashInput{Password: "password", MasterKey: masterKey}).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, ports.PasswordTokenRequest{Email: "alice@example.com", AuthHash: "auth-hash"}).Return(ports.TokenResponse{}, twoFactorError("0", "1", "3"))

	result, err := svc.BeginLogin(context.Background(), LoginInput{Email: "alice@example.com", Password: "password"})
	require.NoError(t, err)
	require.NotNil(t, result.Challenge)
	assert.Nil(t, result.Login)
	assert.Equal(t, []ports.TwoFactorProvider{ports.TwoFactorProviderAuthenticator, ports.TwoFactorProviderEmail, ports.TwoFactorProviderYubiKey}, result.Challenge.Providers)
	assert.Equal(t, "auth-hash", string(result.Challenge.AuthHash.Bytes()))
	assert.Equal(t, masterKey, result.Challenge.MasterKey)
}

func TestCompleteTwoFactorSavesTokensAndUnlocksUserKey(t *testing.T) {
	svc, identity, crypto, store := newTestService(t)
	masterKey := ports.MasterKey{Bytes: []byte("master-key")}
	userKey := ports.UserKey{Bytes: []byte("user-key")}
	tokens := tokenSet("account-2")
	challenge := TwoFactorChallenge{Email: "alice@example.com", AuthHash: ports.NewSecretBytes([]byte("auth-hash")), MasterKey: masterKey, Providers: []ports.TwoFactorProvider{ports.TwoFactorProviderEmail}}

	identity.EXPECT().CompleteTwoFactor(mock.Anything, ports.TwoFactorTokenRequest{Email: "alice@example.com", AuthHash: "auth-hash", Provider: ports.TwoFactorProviderEmail, Code: "123456", Remember: true}).Return(ports.TokenResponse{Tokens: tokens, AccountID: "account-2", EncryptedUserKey: "enc-user-key"}, nil)
	crypto.EXPECT().UnlockUserKey(mock.Anything, ports.UserKeyInput{MasterKey: masterKey, EncryptedUserKey: "enc-user-key"}).Return(userKey, nil)
	store.EXPECT().SaveTokens(mock.Anything, mock.MatchedBy(func(got ports.TokenSet) bool { return got.AccountID == "account-2" })).Return(nil)

	result, err := svc.CompleteTwoFactor(context.Background(), challenge, ports.TwoFactorProviderEmail, "123456", true)
	require.NoError(t, err)
	assert.Equal(t, "account-2", result.AccountID)
	assert.Equal(t, userKey.Bytes, result.UserKey.Bytes)
}

func TestBeginLoginInvalidCredentialsPropagatesUnauthenticated(t *testing.T) {
	svc, identity, crypto, _ := newTestService(t)
	masterKey := ports.MasterKey{Bytes: []byte("master-key")}

	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, mock.Anything).Return(ports.TokenResponse{}, &errors.Error{Kind: errors.KindUnauthenticated, Op: "identity.LoginPassword", Code: "invalid_grant"})

	_, err := svc.BeginLogin(context.Background(), LoginInput{Email: "alice@example.com", Password: "password"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindUnauthenticated))
}

func TestBeginLoginRejectsUnsupportedTwoFactorProviders(t *testing.T) {
	svc, identity, crypto, _ := newTestService(t)
	masterKey := ports.MasterKey{Bytes: []byte("master-key")}

	identity.EXPECT().Prelogin(mock.Anything, "alice@example.com").Return(ports.PreloginResult{KDF: ports.KDFConfig{Type: "PBKDF2", Iterations: 600000}}, nil)
	crypto.EXPECT().DeriveMasterKey(mock.Anything, mock.Anything).Return(masterKey, nil)
	crypto.EXPECT().MakeAuthHash(mock.Anything, mock.Anything).Return(ports.AuthHash("auth-hash"), nil)
	identity.EXPECT().LoginPassword(mock.Anything, mock.Anything).Return(ports.TokenResponse{}, twoFactorError("7"))

	_, err := svc.BeginLogin(context.Background(), LoginInput{Email: "alice@example.com", Password: "password"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindUnsupported))
}

func TestTwoFactorProviderMappings(t *testing.T) {
	tests := map[string]ports.TwoFactorProvider{
		"0": ports.TwoFactorProviderAuthenticator,
		"1": ports.TwoFactorProviderEmail,
		"2": ports.TwoFactorProviderDuo,
		"3": ports.TwoFactorProviderYubiKey,
	}
	for raw, want := range tests {
		got, ok := mapProvider(raw)
		require.True(t, ok)
		assert.Equal(t, want, got)
	}
}

func TestCompleteTwoFactorRejectsProviderOutsideChallenge(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	_, err := svc.CompleteTwoFactor(context.Background(), TwoFactorChallenge{Providers: []ports.TwoFactorProvider{ports.TwoFactorProviderEmail}}, ports.TwoFactorProviderAuthenticator, "123456", false)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errors.KindUnsupported))
}

func newTestService(t *testing.T) (*Service, *mocks.MockIdentityClient, *mocks.MockCryptoEngine, *mocks.MockTokenStore) {
	t.Helper()
	identity := mocks.NewMockIdentityClient(t)
	crypto := mocks.NewMockCryptoEngine(t)
	store := mocks.NewMockTokenStore(t)
	svc := NewService(Dependencies{Identity: identity, Crypto: crypto, Tokens: store})
	return svc, identity, crypto, store
}

func tokenSet(accountID string) ports.TokenSet {
	return ports.TokenSet{
		AccountID:    accountID,
		AccessToken:  ports.NewSecretBytes([]byte("access")),
		RefreshToken: ports.NewSecretBytes([]byte("refresh")),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
}

func twoFactorError(providers ...string) error {
	return &errors.Error{Kind: errors.KindTwoFactorRequired, Op: "identity.LoginPassword", Code: "two_factor_required", TwoFactorProviders: providers}
}
