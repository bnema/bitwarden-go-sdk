package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bnema/bitwarden-go-sdk/internal/adapters/http/dto"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

// VaultClient implements ports.APIClient by calling the Bitwarden API over
// HTTP.
type VaultClient struct {
	baseURL       string
	client        *http.Client
	tokenProvider func(context.Context) (ports.SecretBytes, error)
}

// NewVaultClient creates a VaultClient that sends requests to the given
// baseAPIURL. The provided client is cloned so its CheckRedirect can be set
// to reject cross-origin redirects. The tokenProvider is called on each
// request to supply the Bearer token.
func NewVaultClient(baseAPIURL string, client *http.Client, tokenProvider func(context.Context) (ports.SecretBytes, error)) (*VaultClient, error) {
	if baseAPIURL == "" {
		return nil, fmt.Errorf("api URL must not be empty")
	}
	parsedURL, err := url.Parse(baseAPIURL)
	if err != nil {
		return nil, fmt.Errorf("invalid api URL %q: %w", baseAPIURL, err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("api URL %q must have http or https scheme", baseAPIURL)
	}
	if parsedURL.Host == "" {
		return nil, fmt.Errorf("api URL %q must have a host", baseAPIURL)
	}

	cloned := &http.Client{
		Transport: client.Transport,
		Timeout:   client.Timeout,
		Jar:       client.Jar,
	}
	cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		orig := via[0].URL
		if req.URL.Scheme != orig.Scheme || req.URL.Host != orig.Host {
			return fmt.Errorf("redirect rejected from %s://%s to %s://%s", orig.Scheme, orig.Host, req.URL.Scheme, req.URL.Host)
		}
		return nil
	}

	return &VaultClient{
		baseURL:       strings.TrimRight(baseAPIURL, "/"),
		client:        cloned,
		tokenProvider: tokenProvider,
	}, nil
}

// ---------------------------------------------------------------------------
// APIClient interface implementation
// ---------------------------------------------------------------------------

// Sync fetches the user's vault data.
func (c *VaultClient) Sync(ctx context.Context, opts ports.SyncOptions) (ports.SyncResult, error) {
	u := c.baseURL + "/sync"
	if opts.ExcludeDomains {
		u += "?excludeDomains=true"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ports.SyncResult{}, fmt.Errorf("create sync request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.SyncResult{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.SyncResult{}, fmt.Errorf("sync request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.SyncResult{}, c.parseErrorResponse(resp)
	}

	var syncResp dto.SyncResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return ports.SyncResult{}, fmt.Errorf("decode sync response: %w", err)
	}

	return c.mapSyncResult(syncResp), nil
}

// Config fetches server configuration.
func (c *VaultClient) Config(ctx context.Context) (ports.ServerConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/config", nil)
	if err != nil {
		return ports.ServerConfig{}, fmt.Errorf("create config request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	setBitwardenClientHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.ServerConfig{}, fmt.Errorf("config request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.ServerConfig{}, c.parseErrorResponse(resp)
	}

	var cfg dto.ConfigResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return ports.ServerConfig{}, fmt.Errorf("decode config response: %w", err)
	}

	return ports.ServerConfig{
		Version:      cfg.Version,
		FeatureFlags: cfg.FeatureFlags,
		ServerName:   cfg.ServerName,
	}, nil
}

// AccountProfile fetches the user's account profile.
func (c *VaultClient) AccountProfile(ctx context.Context) (ports.AccountProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/accounts/profile", nil)
	if err != nil {
		return ports.AccountProfile{}, fmt.Errorf("create account profile request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.AccountProfile{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.AccountProfile{}, fmt.Errorf("account profile request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.AccountProfile{}, c.parseErrorResponse(resp)
	}

	var profile dto.AccountProfileResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return ports.AccountProfile{}, fmt.Errorf("decode account profile response: %w", err)
	}

	return ports.AccountProfile{
		ID:                      profile.ID,
		Email:                   profile.Email,
		Name:                    profile.Name,
		EmailVerified:           profile.EmailVerified,
		Premium:                 profile.Premium,
		PremiumFromOrganization: profile.PremiumFromOrganization,
		Culture:                 profile.Culture,
		TwoFactorEnabled:        profile.TwoFactorEnabled,
		ForcePasswordReset:      profile.ForcePasswordReset,
		UsesKeyConnector:        profile.UsesKeyConnector,
		VerifyDevices:           profile.VerifyDevices,
	}, nil
}

// Subscription fetches the user's subscription information.
func (c *VaultClient) Subscription(ctx context.Context) (ports.Subscription, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/accounts/subscription", nil)
	if err != nil {
		return ports.Subscription{}, fmt.Errorf("create subscription request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.Subscription{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.Subscription{}, fmt.Errorf("subscription request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.Subscription{}, c.parseErrorResponse(resp)
	}

	var sub dto.SubscriptionResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&sub); err != nil {
		return ports.Subscription{}, fmt.Errorf("decode subscription response: %w", err)
	}

	premium := sub.StorageName != "" && sub.StorageName != "Free"
	return ports.Subscription{
		Plan:         sub.StorageName,
		IsPremium:    premium,
		StorageName:  sub.StorageName,
		StorageGB:    sub.StorageGB,
		MaxStorageGB: sub.MaxStorageGB,
	}, nil
}

// CreateCipher creates a new cipher via POST /ciphers.
func (c *VaultClient) CreateCipher(ctx context.Context, cipher ports.EncryptedCipher) (ports.EncryptedCipher, error) {
	body := c.encryptedCipherToRequestDTO(cipher)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("marshal cipher: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/ciphers", bytes.NewReader(reqBody))
	if err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("create cipher request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.EncryptedCipher{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("create cipher: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return ports.EncryptedCipher{}, c.parseErrorResponse(resp)
	}

	var cipherResp dto.CipherDTO
	if err := json.NewDecoder(resp.Body).Decode(&cipherResp); err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("decode cipher response: %w", err)
	}

	return c.mapCipherDTOToPorts(cipherResp), nil
}

// UpdateCipher updates an existing cipher via PUT /ciphers/{id}.
func (c *VaultClient) UpdateCipher(ctx context.Context, id string, cipher ports.EncryptedCipher) (ports.EncryptedCipher, error) {
	body := c.encryptedCipherToRequestDTO(cipher)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("marshal cipher: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/ciphers/"+url.PathEscape(id), bytes.NewReader(reqBody))
	if err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("update cipher request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.EncryptedCipher{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("update cipher: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.EncryptedCipher{}, c.parseErrorResponse(resp)
	}

	var cipherResp dto.CipherDTO
	if err := json.NewDecoder(resp.Body).Decode(&cipherResp); err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("decode cipher response: %w", err)
	}

	return c.mapCipherDTOToPorts(cipherResp), nil
}

// DeleteCipher permanently deletes a cipher via DELETE /ciphers/{id}.
func (c *VaultClient) DeleteCipher(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/ciphers/"+url.PathEscape(id), nil)
	if err != nil {
		return fmt.Errorf("delete cipher request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("delete cipher: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.parseErrorResponse(resp)
	}

	return nil
}

// TrashCipher soft-deletes (trashes) a cipher via PUT /ciphers/{id}/delete.
func (c *VaultClient) TrashCipher(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/ciphers/"+url.PathEscape(id)+"/delete", nil)
	if err != nil {
		return fmt.Errorf("trash cipher request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("trash cipher: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.parseErrorResponse(resp)
	}

	return nil
}

// RestoreCipher restores a trashed cipher via PUT /ciphers/{id}/restore.
func (c *VaultClient) RestoreCipher(ctx context.Context, id string) (ports.EncryptedCipher, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/ciphers/"+url.PathEscape(id)+"/restore", nil)
	if err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("restore cipher request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.EncryptedCipher{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("restore cipher: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.EncryptedCipher{}, c.parseErrorResponse(resp)
	}

	var cipherResp dto.CipherDTO
	if err := json.NewDecoder(resp.Body).Decode(&cipherResp); err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("decode cipher response: %w", err)
	}

	return c.mapCipherDTOToPorts(cipherResp), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Cipher DTO mapping helpers
// ---------------------------------------------------------------------------

// encryptedCipherToRequestDTO converts an EncryptedCipher port type into a
// CipherRequestDTO suitable for marshalling as a request body.
// The lower-camel JSON tags on CipherRequestDTO match the Bitwarden
// API expectations for create/update endpoints.
func (c *VaultClient) encryptedCipherToRequestDTO(cipher ports.EncryptedCipher) dto.CipherRequestDTO {
	out := dto.CipherRequestDTO{
		Type:     cipher.Type,
		Name:     cipher.Name,
		Favorite: cipher.Favorite,
	}

	if cipher.Notes != "" {
		n := cipher.Notes
		out.Notes = &n
	}
	if cipher.FolderID != "" {
		f := cipher.FolderID
		out.FolderID = &f
	}

	if cipher.Login != nil {
		uris := make([]dto.LoginURIRequestDTO, len(cipher.Login.URIs))
		for i, u := range cipher.Login.URIs {
			uriDTO := dto.LoginURIRequestDTO{
				URI:         u.URI,
				URIChecksum: u.URIChecksum,
			}
			if u.Match != 0 {
				m := u.Match
				uriDTO.Match = &m
			}
			uris[i] = uriDTO
		}
		out.Login = &dto.LoginRequestDTO{
			Username: cipher.Login.Username,
			Password: cipher.Login.Password,
			TOTP:     cipher.Login.TOTP,
			URIs:     uris,
		}
	}

	if cipher.SecureNote != nil {
		out.SecureNote = &dto.SecureNoteRequestDTO{
			Type: cipher.SecureNote.Type,
		}
	}

	if cipher.Card != nil {
		out.Card = &dto.CardRequestDTO{
			CardholderName: cipher.Card.CardholderName,
			Brand:          cipher.Card.Brand,
			Number:         cipher.Card.Number,
			ExpMonth:       cipher.Card.ExpMonth,
			ExpYear:        cipher.Card.ExpYear,
			Code:           cipher.Card.Code,
		}
	}

	if cipher.Identity != nil {
		out.Identity = &dto.IdentityRequestDTO{
			Title:          cipher.Identity.Title,
			FirstName:      cipher.Identity.FirstName,
			MiddleName:     cipher.Identity.MiddleName,
			LastName:       cipher.Identity.LastName,
			Address1:       cipher.Identity.Address1,
			Address2:       cipher.Identity.Address2,
			Address3:       cipher.Identity.Address3,
			City:           cipher.Identity.City,
			State:          cipher.Identity.State,
			PostalCode:     cipher.Identity.PostalCode,
			Country:        cipher.Identity.Country,
			Company:        cipher.Identity.Company,
			Email:          cipher.Identity.Email,
			Phone:          cipher.Identity.Phone,
			SSN:            cipher.Identity.SSN,
			Username:       cipher.Identity.Username,
			PassportNumber: cipher.Identity.PassportNumber,
			LicenseNumber:  cipher.Identity.LicenseNumber,
		}
	}

	if len(cipher.Fields) > 0 {
		out.Fields = make([]dto.FieldRequestDTO, len(cipher.Fields))
		for i, f := range cipher.Fields {
			out.Fields[i] = dto.FieldRequestDTO{
				Name:     f.Name,
				Value:    f.Value,
				Type:     f.Type,
				LinkedID: f.LinkedID,
			}
		}
	}

	return out
}

// mapCipherDTOToPorts converts a CipherDTO (from an API response) into an
// EncryptedCipher port type.
func (c *VaultClient) mapCipherDTOToPorts(ct dto.CipherDTO) ports.EncryptedCipher {
	cipher := ports.EncryptedCipher{
		ID:       ct.ID,
		Type:     ct.Type,
		Name:     ct.Name,
		Favorite: ct.Favorite,
	}
	if ct.Notes != nil {
		cipher.Notes = *ct.Notes
	}
	if ct.FolderID != nil {
		cipher.FolderID = *ct.FolderID
	}
	if ct.OrganizationID != nil {
		cipher.OrganizationID = *ct.OrganizationID
	}
	if ct.Key != nil {
		cipher.Key = *ct.Key
	}

	if ct.Login != nil {
		login := &ports.EncryptedLoginCipher{
			Username: ct.Login.Username,
			Password: ct.Login.Password,
			TOTP:     ct.Login.TOTP,
			URIs:     make([]ports.EncryptedLoginURI, 0, len(ct.Login.URIs)),
		}
		for _, u := range ct.Login.URIs {
			uri := ports.EncryptedLoginURI{
				URI:         u.URI,
				URIChecksum: u.URIChecksum,
			}
			if u.Match != nil {
				uri.Match = *u.Match
			}
			login.URIs = append(login.URIs, uri)
		}
		cipher.Login = login
	}

	if ct.SecureNote != nil {
		cipher.SecureNote = &ports.EncryptedSecureNoteCipher{
			Type: ct.SecureNote.Type,
		}
	}

	if ct.Card != nil {
		cipher.Card = &ports.EncryptedCardCipher{
			CardholderName: ct.Card.CardholderName,
			Brand:          ct.Card.Brand,
			Number:         ct.Card.Number,
			ExpMonth:       ct.Card.ExpMonth,
			ExpYear:        ct.Card.ExpYear,
			Code:           ct.Card.Code,
		}
	}

	if ct.Identity != nil {
		cipher.Identity = &ports.EncryptedIdentityCipher{
			Title:          ct.Identity.Title,
			FirstName:      ct.Identity.FirstName,
			MiddleName:     ct.Identity.MiddleName,
			LastName:       ct.Identity.LastName,
			Address1:       ct.Identity.Address1,
			Address2:       ct.Identity.Address2,
			Address3:       ct.Identity.Address3,
			City:           ct.Identity.City,
			State:          ct.Identity.State,
			PostalCode:     ct.Identity.PostalCode,
			Country:        ct.Identity.Country,
			Company:        ct.Identity.Company,
			Email:          ct.Identity.Email,
			Phone:          ct.Identity.Phone,
			SSN:            ct.Identity.SSN,
			Username:       ct.Identity.Username,
			PassportNumber: ct.Identity.PassportNumber,
			LicenseNumber:  ct.Identity.LicenseNumber,
		}
	}

	if len(ct.Fields) > 0 {
		cipher.Fields = make([]ports.EncryptedCipherField, 0, len(ct.Fields))
		for _, field := range ct.Fields {
			cipher.Fields = append(cipher.Fields, ports.EncryptedCipherField{
				Name:     field.Name,
				Value:    field.Value,
				Type:     field.Type,
				LinkedID: field.LinkedID,
			})
		}
	}

	return cipher
}

// setAuthHeader calls the token provider and sets the Authorization header.
func (c *VaultClient) setAuthHeader(ctx context.Context, req *http.Request) error {
	token, err := c.tokenProvider(ctx)
	if err != nil {
		return fmt.Errorf("token provider: %w", err)
	}
	setBitwardenClientHeaders(req)
	req.Header.Set("Authorization", "Bearer "+string(token.Bytes()))
	return nil
}

// parseErrorResponse handles error responses for vault API endpoints.
// It checks for Retry-After headers for rate limiting and maps 401 to
// KindUnauthenticated.
func (c *VaultClient) parseErrorResponse(resp *http.Response) error {
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		seconds, err := strconv.Atoi(retryAfter)
		if err == nil && seconds > 0 {
			return &coreerrors.Error{
				Kind:       coreerrors.KindRateLimited,
				Status:     resp.StatusCode,
				RetryAfter: seconds,
			}
		}
	}

	// Drain body — do not read or log the content.
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return &coreerrors.Error{
			Kind:   coreerrors.KindUnauthenticated,
			Status: resp.StatusCode,
		}
	default:
		return &coreerrors.Error{
			Kind:   coreerrors.KindUnknown,
			Status: resp.StatusCode,
		}
	}
}

// mapSyncResult converts a DTO sync response into the port SyncResult.
func (c *VaultClient) mapSyncResult(s dto.SyncResponseDTO) ports.SyncResult {
	result := ports.SyncResult{
		Profile: ports.AccountProfile{
			ID:                      s.Profile.ID,
			Email:                   s.Profile.Email,
			Name:                    s.Profile.Name,
			EmailVerified:           s.Profile.EmailVerified,
			Premium:                 s.Profile.Premium,
			PremiumFromOrganization: s.Profile.PremiumFromOrganization,
			TwoFactorEnabled:        s.Profile.TwoFactorEnabled,
		},
		Folders: make([]ports.EncryptedFolder, 0, len(s.Folders)),
		Ciphers: make([]ports.EncryptedCipher, 0, len(s.Ciphers)),
	}

	for _, f := range s.Folders {
		result.Folders = append(result.Folders, ports.EncryptedFolder{
			ID:   f.ID,
			Name: f.Name,
		})
	}

	for _, ct := range s.Ciphers {
		cipher := ports.EncryptedCipher{
			ID:       ct.ID,
			Type:     ct.Type,
			Name:     ct.Name,
			Favorite: ct.Favorite,
		}
		if ct.Notes != nil {
			cipher.Notes = *ct.Notes
		}
		if ct.FolderID != nil {
			cipher.FolderID = *ct.FolderID
		}
		if ct.OrganizationID != nil {
			cipher.OrganizationID = *ct.OrganizationID
		}
		if ct.Key != nil {
			cipher.Key = *ct.Key
		}

		if ct.Login != nil {
			login := &ports.EncryptedLoginCipher{
				Username: ct.Login.Username,
				Password: ct.Login.Password,
				TOTP:     ct.Login.TOTP,
				URIs:     make([]ports.EncryptedLoginURI, 0, len(ct.Login.URIs)),
			}
			for _, u := range ct.Login.URIs {
				uri := ports.EncryptedLoginURI{
					URI:         u.URI,
					URIChecksum: u.URIChecksum,
				}
				if u.Match != nil {
					uri.Match = *u.Match
				}
				login.URIs = append(login.URIs, uri)
			}
			cipher.Login = login
		}

		if ct.SecureNote != nil {
			cipher.SecureNote = &ports.EncryptedSecureNoteCipher{
				Type: ct.SecureNote.Type,
			}
		}

		if ct.Card != nil {
			cipher.Card = &ports.EncryptedCardCipher{
				CardholderName: ct.Card.CardholderName,
				Brand:          ct.Card.Brand,
				Number:         ct.Card.Number,
				ExpMonth:       ct.Card.ExpMonth,
				ExpYear:        ct.Card.ExpYear,
				Code:           ct.Card.Code,
			}
		}

		if ct.Identity != nil {
			cipher.Identity = &ports.EncryptedIdentityCipher{
				Title:          ct.Identity.Title,
				FirstName:      ct.Identity.FirstName,
				MiddleName:     ct.Identity.MiddleName,
				LastName:       ct.Identity.LastName,
				Address1:       ct.Identity.Address1,
				Address2:       ct.Identity.Address2,
				Address3:       ct.Identity.Address3,
				City:           ct.Identity.City,
				State:          ct.Identity.State,
				PostalCode:     ct.Identity.PostalCode,
				Country:        ct.Identity.Country,
				Company:        ct.Identity.Company,
				Email:          ct.Identity.Email,
				Phone:          ct.Identity.Phone,
				SSN:            ct.Identity.SSN,
				Username:       ct.Identity.Username,
				PassportNumber: ct.Identity.PassportNumber,
				LicenseNumber:  ct.Identity.LicenseNumber,
			}
		}

		if len(ct.Fields) > 0 {
			cipher.Fields = make([]ports.EncryptedCipherField, 0, len(ct.Fields))
			for _, field := range ct.Fields {
				cipher.Fields = append(cipher.Fields, ports.EncryptedCipherField{
					Name:     field.Name,
					Value:    field.Value,
					Type:     field.Type,
					LinkedID: field.LinkedID,
				})
			}
		}

		result.Ciphers = append(result.Ciphers, cipher)
	}

	return result
}

// ---------------------------------------------------------------------------
// Folder operations
// ---------------------------------------------------------------------------

// ListFolders fetches all folders via GET /folders.
func (c *VaultClient) ListFolders(ctx context.Context) ([]ports.EncryptedFolder, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/folders", nil)
	if err != nil {
		return nil, fmt.Errorf("create list folders request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list folders: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	var folderDTOs []dto.FolderDTO
	if err := json.NewDecoder(resp.Body).Decode(&folderDTOs); err != nil {
		return nil, fmt.Errorf("decode list folders response: %w", err)
	}

	folders := make([]ports.EncryptedFolder, 0, len(folderDTOs))
	for _, f := range folderDTOs {
		folders = append(folders, ports.EncryptedFolder{
			ID:   f.ID,
			Name: f.Name,
		})
	}

	return folders, nil
}

// CreateFolder creates a new folder via POST /folders.
func (c *VaultClient) CreateFolder(ctx context.Context, folder ports.EncryptedFolder) (ports.EncryptedFolder, error) {
	body := dto.FolderRequestDTO{Name: folder.Name}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return ports.EncryptedFolder{}, fmt.Errorf("marshal folder: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/folders", bytes.NewReader(reqBody))
	if err != nil {
		return ports.EncryptedFolder{}, fmt.Errorf("create folder request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.EncryptedFolder{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.EncryptedFolder{}, fmt.Errorf("create folder: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return ports.EncryptedFolder{}, c.parseErrorResponse(resp)
	}

	var folderResp dto.FolderDTO
	if err := json.NewDecoder(resp.Body).Decode(&folderResp); err != nil {
		return ports.EncryptedFolder{}, fmt.Errorf("decode folder response: %w", err)
	}

	return ports.EncryptedFolder{
		ID:   folderResp.ID,
		Name: folderResp.Name,
	}, nil
}

// UpdateFolder updates an existing folder via PUT /folders/{id}.
func (c *VaultClient) UpdateFolder(ctx context.Context, id string, folder ports.EncryptedFolder) (ports.EncryptedFolder, error) {
	body := dto.FolderRequestDTO{Name: folder.Name}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return ports.EncryptedFolder{}, fmt.Errorf("marshal folder: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/folders/"+url.PathEscape(id), bytes.NewReader(reqBody))
	if err != nil {
		return ports.EncryptedFolder{}, fmt.Errorf("update folder request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.EncryptedFolder{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.EncryptedFolder{}, fmt.Errorf("update folder: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.EncryptedFolder{}, c.parseErrorResponse(resp)
	}

	var folderResp dto.FolderDTO
	if err := json.NewDecoder(resp.Body).Decode(&folderResp); err != nil {
		return ports.EncryptedFolder{}, fmt.Errorf("decode folder response: %w", err)
	}

	return ports.EncryptedFolder{
		ID:   folderResp.ID,
		Name: folderResp.Name,
	}, nil
}

// DeleteFolder deletes a folder via DELETE /folders/{id}.
func (c *VaultClient) DeleteFolder(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/folders/"+url.PathEscape(id), nil)
	if err != nil {
		return fmt.Errorf("delete folder request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("delete folder: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.parseErrorResponse(resp)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Attachment operations
// ---------------------------------------------------------------------------

// GetAttachment fetches attachment metadata via GET /ciphers/{cipherID}/attachment/{attachmentID}.
func (c *VaultClient) GetAttachment(ctx context.Context, cipherID, attachmentID string) (ports.EncryptedAttachmentMetadata, error) {
	u := c.baseURL + "/ciphers/" + url.PathEscape(cipherID) + "/attachment/" + url.PathEscape(attachmentID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ports.EncryptedAttachmentMetadata{}, fmt.Errorf("create get attachment request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, req); err != nil {
		return ports.EncryptedAttachmentMetadata{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ports.EncryptedAttachmentMetadata{}, fmt.Errorf("get attachment: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.EncryptedAttachmentMetadata{}, c.parseErrorResponse(resp)
	}

	var attResp dto.AttachmentResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&attResp); err != nil {
		return ports.EncryptedAttachmentMetadata{}, fmt.Errorf("decode attachment response: %w", err)
	}

	return ports.EncryptedAttachmentMetadata{
		ID:       attResp.ID,
		CipherID: cipherID,
		FileName: attResp.FileName,
		Key:      attResp.Key,
		Size:     attResp.Size,
		SizeName: attResp.SizeName,
		URL:      attResp.URL,
	}, nil
}

// InitAttachmentUpload initialises an attachment upload via POST /ciphers/{cipherID}/attachment/v2.
func (c *VaultClient) InitAttachmentUpload(ctx context.Context, req ports.AttachmentUploadRequest) (ports.AttachmentUploadResponse, error) {
	reqBody, err := json.Marshal(dto.AttachmentRequestDTO{
		FileName: req.FileName,
		Key:      req.Key,
		FileSize: req.FileSize,
	})
	if err != nil {
		return ports.AttachmentUploadResponse{}, fmt.Errorf("marshal attachment request: %w", err)
	}

	u := c.baseURL + "/ciphers/" + url.PathEscape(req.CipherID) + "/attachment/v2"

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(reqBody))
	if err != nil {
		return ports.AttachmentUploadResponse{}, fmt.Errorf("create init attachment upload request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, httpReq); err != nil {
		return ports.AttachmentUploadResponse{}, err
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return ports.AttachmentUploadResponse{}, fmt.Errorf("init attachment upload: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return ports.AttachmentUploadResponse{}, c.parseErrorResponse(resp)
	}

	var uploadResp dto.AttachmentUploadDataResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		return ports.AttachmentUploadResponse{}, fmt.Errorf("decode attachment upload response: %w", err)
	}

	result := ports.AttachmentUploadResponse{
		AttachmentID:   uploadResp.AttachmentID,
		FileUploadType: uploadResp.FileUploadType,
	}
	if uploadResp.URL != nil {
		result.URL = *uploadResp.URL
	}

	// Map CipherResponse if present.
	if uploadResp.CipherResponse != nil {
		result.Cipher = ports.EncryptedCipher{
			ID: uploadResp.CipherResponse.ID,
		}
	}

	return result, nil
}

// UploadAttachmentDirect uploads attachment content via POST /ciphers/{cipherID}/attachment/{attachmentID}
// using multipart/form-data with field name "data".
// The pipe and goroutine are started only after setAuthHeader succeeds to avoid
// leaking goroutines when the token provider returns an error.
func (c *VaultClient) UploadAttachmentDirect(ctx context.Context, cipherID, attachmentID string, content io.Reader) error {
	u := c.baseURL + "/ciphers/" + url.PathEscape(cipherID) + "/attachment/" + url.PathEscape(attachmentID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return fmt.Errorf("create upload attachment request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "multipart/form-data; boundary=placeholder")

	if err := c.setAuthHeader(ctx, httpReq); err != nil {
		return err
	}

	// Only start the pipe and multipart pump after auth is confirmed.
	pr, pw := io.Pipe()
	mp := multipart.NewWriter(pw)

	httpReq.Body = pr
	httpReq.Header.Set("Content-Type", mp.FormDataContentType())

	go func() {
		var writeErr error
		defer func() {
			_ = mp.Close()
			_ = pw.CloseWithError(writeErr)
		}()

		dataField, err := mp.CreateFormField("data")
		if err != nil {
			writeErr = fmt.Errorf("create multipart form field: %w", err)
			return
		}

		if _, err := io.Copy(dataField, content); err != nil {
			writeErr = fmt.Errorf("copy content to multipart field: %w", err)
			return
		}
	}()

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("upload attachment direct: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.parseErrorResponse(resp)
	}

	return nil
}

// UploadAttachmentExternal uploads attachment content by PUTing to the
// provided uploadURL. No authorization header is sent to external URLs.
func (c *VaultClient) UploadAttachmentExternal(ctx context.Context, uploadURL string, content io.Reader) error {
	// Validate the URL is http/https.
	parsedURL, err := url.Parse(uploadURL)
	if err != nil {
		return fmt.Errorf("parse upload URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("upload URL must have http or https scheme, got %q", parsedURL.Scheme)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, content)
	if err != nil {
		return fmt.Errorf("create external upload request: %w", err)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("external upload: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return &coreerrors.Error{
			Kind:   coreerrors.KindUnknown,
			Status: resp.StatusCode,
		}
	}

	return nil
}

// RenewAttachmentUploadURL renews an attachment upload URL via
// GET /ciphers/{cipherID}/attachment/{attachmentID}/renew.
func (c *VaultClient) RenewAttachmentUploadURL(ctx context.Context, cipherID, attachmentID string) (ports.AttachmentUploadResponse, error) {
	u := c.baseURL + "/ciphers/" + url.PathEscape(cipherID) + "/attachment/" + url.PathEscape(attachmentID) + "/renew"

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ports.AttachmentUploadResponse{}, fmt.Errorf("create renew attachment URL request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, httpReq); err != nil {
		return ports.AttachmentUploadResponse{}, err
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return ports.AttachmentUploadResponse{}, fmt.Errorf("renew attachment URL: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ports.AttachmentUploadResponse{}, c.parseErrorResponse(resp)
	}

	var renewResp dto.AttachmentUploadDataResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&renewResp); err != nil {
		return ports.AttachmentUploadResponse{}, fmt.Errorf("decode renew response: %w", err)
	}

	result := ports.AttachmentUploadResponse{
		AttachmentID:   renewResp.AttachmentID,
		FileUploadType: renewResp.FileUploadType,
	}
	if renewResp.URL != nil {
		result.URL = *renewResp.URL
	}

	return result, nil
}

// DownloadAttachment downloads the attachment bytes from the given URL.
// The URL must be http or https. No auth header is sent for absolute attachment URLs.
// Success (200) returns the body as an io.ReadCloser. Non-200 responses drain
// the body and return an error.
func (c *VaultClient) DownloadAttachment(ctx context.Context, attachmentURL string) (io.ReadCloser, error) {
	parsedURL, err := url.Parse(attachmentURL)
	if err != nil {
		return nil, fmt.Errorf("parse attachment URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("attachment URL must have http or https scheme, got %q", parsedURL.Scheme)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, attachmentURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create download attachment request: %w", err)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("download attachment: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, &coreerrors.Error{
			Kind:   coreerrors.KindUnknown,
			Status: resp.StatusCode,
		}
	}

	return resp.Body, nil
}

// DeleteAttachment deletes an attachment via DELETE /ciphers/{cipherID}/attachment/{attachmentID}.
// Returns the updated cipher if present in the response.
func (c *VaultClient) DeleteAttachment(ctx context.Context, cipherID, attachmentID string) (ports.EncryptedCipher, error) {
	u := c.baseURL + "/ciphers/" + url.PathEscape(cipherID) + "/attachment/" + url.PathEscape(attachmentID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("create delete attachment request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")

	if err := c.setAuthHeader(ctx, httpReq); err != nil {
		return ports.EncryptedCipher{}, err
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("delete attachment: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return ports.EncryptedCipher{}, c.parseErrorResponse(resp)
	}

	// If no content, return empty cipher.
	if resp.StatusCode == http.StatusNoContent {
		return ports.EncryptedCipher{}, nil
	}

	var deleteResp dto.DeleteAttachmentResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&deleteResp); err != nil {
		return ports.EncryptedCipher{}, fmt.Errorf("decode delete attachment response: %w", err)
	}

	cipher := ports.EncryptedCipher{}
	if deleteResp.Cipher != nil {
		cipher.ID = deleteResp.Cipher.ID
	}

	return cipher, nil
}

// Ensure compile-time check that VaultClient implements ports.APIClient.
var _ ports.APIClient = (*VaultClient)(nil)
