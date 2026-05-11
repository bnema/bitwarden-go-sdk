// Package dto contains raw Bitwarden request and response models used only
// by the internal HTTP adapters after endpoint mapping is approved.
package dto

// PreloginRequest is sent to POST /accounts/prelogin/password.
type PreloginRequest struct {
	Email string `json:"email"`
}

// PreloginResponse is received from POST /accounts/prelogin/password.
type PreloginResponse struct {
	Kdf            int `json:"Kdf"`
	KdfIterations  int `json:"KdfIterations"`
	KdfMemory      int `json:"KdfMemory,omitempty"`
	KdfParallelism int `json:"KdfParallelism,omitempty"`
}

// TokenResponse is received from POST /connect/token on success.
type TokenResponse struct {
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	TokenType      string `json:"token_type"`
	ExpiresIn      int    `json:"expires_in"`
	Key            string `json:"Key"`
	AccountID      string `json:"AccountId,omitempty"`
	TwoFactorToken string `json:"TwoFactorToken,omitempty"`
}

// TokenErrorResponse is received from POST /connect/token on error (HTTP 400).
type TokenErrorResponse struct {
	Error               string         `json:"error"`
	ErrorDescription    string         `json:"error_description"`
	TwoFactorProviders2 map[string]any `json:"TwoFactorProviders2,omitempty"`
}
