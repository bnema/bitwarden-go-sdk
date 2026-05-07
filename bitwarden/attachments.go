package bitwarden

import (
	"context"
	"io"

	coreattach "github.com/bnema/bitwarden-go-sdk/internal/core/attachments"
	coreerrors "github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/secretmem"
)

// Attachment is a public attachment model.
type Attachment struct {
	ID       string
	CipherID string
	FileName string
	Size     int64
	SizeName string
	URL      string
}

// AttachmentUploadOptions contains parameters for uploading an attachment.
type AttachmentUploadOptions struct {
	ItemID   string
	FileName string
	Size     int64
	Reader   io.Reader
}

// Attachments is the public facade for attachment operations.
type Attachments struct {
	client *Client
}

// attachmentsService creates a core attachments.Service from the client's
// current state.
func (a *Attachments) attachmentsService() *coreattach.Service {
	a.client.mu.RLock()
	userKey := ports.UserKey{Bytes: secretmem.Clone(a.client.userKey.Bytes)}
	a.client.mu.RUnlock()

	return coreattach.NewService(coreattach.Dependencies{
		API:     a.client.api,
		Crypto:  a.client.crypto,
		UserKey: userKey,
		Locked:  a.client.IsLocked(),
	})
}

// Metadata returns attachment metadata with the filename decrypted.
func (a *Attachments) Metadata(ctx context.Context, cipherID, attachmentID string) (Attachment, error) {
	if a.client.IsLocked() {
		return Attachment{}, mapCoreError(&coreerrors.Error{Kind: coreerrors.KindLocked, Op: "Attachments.Metadata", Message: "client is locked"})
	}

	svc := a.attachmentsService()
	att, err := svc.Metadata(ctx, cipherID, attachmentID)
	if err != nil {
		return Attachment{}, mapCoreError(err)
	}

	return Attachment{
		ID:       att.ID,
		CipherID: att.CipherID,
		FileName: att.FileName,
		Size:     att.Size,
		SizeName: att.SizeName,
		URL:      att.URL,
	}, nil
}

// Upload uploads an attachment from an io.Reader. It generates a random
// 64-byte attachment key internally.
func (a *Attachments) Upload(ctx context.Context, opts AttachmentUploadOptions) (Attachment, error) {
	if a.client.IsLocked() {
		return Attachment{}, mapCoreError(&coreerrors.Error{Kind: coreerrors.KindLocked, Op: "Attachments.Upload", Message: "client is locked"})
	}

	svc := a.attachmentsService()
	att, err := svc.UploadGenerated(ctx, opts.ItemID, opts.FileName, opts.Size, opts.Reader)
	if err != nil {
		return Attachment{}, mapCoreError(err)
	}

	return Attachment{
		ID:       att.ID,
		CipherID: att.CipherID,
		FileName: att.FileName,
		Size:     att.Size,
		SizeName: att.SizeName,
		URL:      att.URL,
	}, nil
}

// Download downloads an attachment and writes its decrypted plaintext to dst.
func (a *Attachments) Download(ctx context.Context, cipherID, attachmentID string, dst io.Writer) error {
	if a.client.IsLocked() {
		return mapCoreError(&coreerrors.Error{Kind: coreerrors.KindLocked, Op: "Attachments.Download", Message: "client is locked"})
	}

	svc := a.attachmentsService()
	err := svc.DownloadByID(ctx, cipherID, attachmentID, dst)
	return mapCoreError(err)
}

// Delete deletes an attachment by cipher ID and attachment ID.
func (a *Attachments) Delete(ctx context.Context, cipherID, attachmentID string) error {
	if a.client.IsLocked() {
		return mapCoreError(&coreerrors.Error{Kind: coreerrors.KindLocked, Op: "Attachments.Delete", Message: "client is locked"})
	}

	svc := a.attachmentsService()
	err := svc.Delete(ctx, cipherID, attachmentID)
	return mapCoreError(err)
}

// Attachments returns the Attachments facade for attachment operations.
func (c *Client) Attachments() *Attachments {
	return &Attachments{client: c}
}
