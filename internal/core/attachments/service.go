// Package attachments owns core use cases for attachment operations.
//
// Core packages must not import adapters.
package attachments

import (
	"context"
	"crypto/rand"
	stderrors "errors"
	"io"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
	"github.com/bnema/bitwarden-go-sdk/internal/secretmem"
)

// Attachment is a plaintext attachment model.
type Attachment struct {
	ID       string
	CipherID string
	FileName string
	Size     int64
	SizeName string
	URL      string
}

// UploadInput contains the parameters for uploading an attachment.
type UploadInput struct {
	CipherID      string
	FileName      string
	Size          int64
	Plaintext     io.Reader
	AttachmentKey ports.AttachmentKey
	WrappedKey    string
}

// Dependencies groups attachment service dependencies.
type Dependencies struct {
	API     ports.APIClient
	Crypto  ports.CryptoEngine
	UserKey ports.UserKey
	Locked  bool
}

// Service provides attachment operations with encryption/decryption.
type Service struct {
	api     ports.APIClient
	crypto  ports.CryptoEngine
	userKey ports.UserKey
	locked  bool
}

// NewService creates an attachment service from Dependencies.
func NewService(deps Dependencies) *Service {
	return &Service{
		api:     deps.API,
		crypto:  deps.Crypto,
		userKey: ports.UserKey{Bytes: secretmem.Clone(deps.UserKey.Bytes)},
		locked:  deps.Locked,
	}
}

// Metadata returns attachment metadata with the filename decrypted.
// Returns KindLocked when the service is locked.
func (s *Service) Metadata(ctx context.Context, cipherID, attachmentID string) (Attachment, error) {
	if s.locked {
		return Attachment{}, &errors.Error{Kind: errors.KindLocked, Op: "attachments.Service.Metadata", Message: "service is locked"}
	}

	meta, err := s.api.GetAttachment(ctx, cipherID, attachmentID)
	if err != nil {
		return Attachment{}, err
	}

	fileName, err := s.crypto.DecryptFolderName(ctx, s.userKey, meta.FileName)
	if err != nil {
		return Attachment{}, err
	}

	return Attachment{
		ID:       meta.ID,
		CipherID: meta.CipherID,
		FileName: fileName,
		Size:     meta.Size,
		SizeName: meta.SizeName,
		URL:      meta.URL,
	}, nil
}

// Upload encrypts and uploads an attachment. On upload failure, it attempts to
// roll back by deleting the partially-created attachment. Returns KindLocked
// when the service is locked.
func (s *Service) Upload(ctx context.Context, input UploadInput) (Attachment, error) {
	if s.locked {
		return Attachment{}, &errors.Error{Kind: errors.KindLocked, Op: "attachments.Service.Upload", Message: "service is locked"}
	}

	encFileName, err := s.crypto.EncryptFolderName(ctx, s.userKey, input.FileName)
	if err != nil {
		return Attachment{}, err
	}

	initResp, err := s.api.InitAttachmentUpload(ctx, ports.AttachmentUploadRequest{
		CipherID: input.CipherID,
		FileName: encFileName,
		Key:      input.WrappedKey,
		FileSize: input.Size,
	})
	if err != nil {
		return Attachment{}, err
	}

	pr, pw := io.Pipe()

	go func() {
		encErr := s.crypto.EncryptAttachment(ctx, input.AttachmentKey, input.Plaintext, pw)
		pw.CloseWithError(encErr)
	}()

	var uploadErr error
	if initResp.FileUploadType == 0 {
		uploadErr = s.api.UploadAttachmentDirect(ctx, input.CipherID, initResp.AttachmentID, pr)
	} else {
		uploadErr = s.api.UploadAttachmentExternal(ctx, initResp.URL, pr)
	}

	// Drain the pipe reader to ensure the encrypt goroutine completes and
	// to capture any encrypt error that was closed into the pipe.
	_, pipeErr := io.Copy(io.Discard, pr)

	// Combine errors: prefer the upload error because it is the caller-visible
	// operation failure. Include the pipe/encryption error when both occurred.
	uploadErrFinal := uploadErr
	if uploadErrFinal != nil && pipeErr != nil {
		uploadErrFinal = stderrors.Join(uploadErrFinal, pipeErr)
	}
	if uploadErrFinal == nil {
		uploadErrFinal = pipeErr
	}

	if uploadErrFinal != nil {
		// Rollback: attempt to delete the partially-uploaded attachment.
		// Use a context that is not cancelled so the delete is not silently
		// skipped when the caller's context has been cancelled or timed out.
		rollbackCtx := context.WithoutCancel(ctx)
		_, rollbackErr := s.api.DeleteAttachment(rollbackCtx, input.CipherID, initResp.AttachmentID)

		if rollbackErr != nil {
			return Attachment{}, &errors.Error{
				Kind:    errors.KindTemporary,
				Op:      "attachments.Service.Upload",
				Code:    "rollback_failed",
				Message: "upload failed and rollback delete failed",
				Cause:   rollbackErr,
			}
		}

		// Rollback succeeded; surface the original error.
		return Attachment{}, uploadErrFinal
	}

	return Attachment{
		ID:       initResp.AttachmentID,
		CipherID: input.CipherID,
		FileName: input.FileName,
		Size:     input.Size,
	}, nil
}

// Download decrypts an attachment stream. The caller provides the encrypted
// content reader and a writer to receive the plaintext. Returns KindLocked
// when the service is locked.
func (s *Service) Download(ctx context.Context, meta ports.EncryptedAttachmentMetadata, encrypted io.Reader, dst io.Writer) error {
	if s.locked {
		return &errors.Error{Kind: errors.KindLocked, Op: "attachments.Service.Download", Message: "service is locked"}
	}

	key, err := s.crypto.DecryptAttachmentKey(ctx, s.userKey, ports.EncryptedAttachment{
		ID:  meta.ID,
		Key: meta.Key,
	})
	if err != nil {
		return err
	}

	return s.crypto.DecryptAttachment(ctx, key, encrypted, dst)
}

// Delete deletes an attachment by cipher ID and attachment ID.
// Returns KindLocked when the service is locked.
func (s *Service) Delete(ctx context.Context, cipherID, attachmentID string) error {
	if s.locked {
		return &errors.Error{Kind: errors.KindLocked, Op: "attachments.Service.Delete", Message: "service is locked"}
	}

	_, err := s.api.DeleteAttachment(ctx, cipherID, attachmentID)
	return err
}

// UploadGenerated generates a random 64-byte attachment key, wraps it with
// the user key, and uploads the plaintext. Returns KindLocked when the
// service is locked.
func (s *Service) UploadGenerated(ctx context.Context, cipherID, fileName string, size int64, plaintext io.Reader) (Attachment, error) {
	if s.locked {
		return Attachment{}, &errors.Error{Kind: errors.KindLocked, Op: "attachments.Service.UploadGenerated", Message: "service is locked"}
	}

	keyBytes := make([]byte, 64)
	if _, err := rand.Read(keyBytes); err != nil {
		return Attachment{}, err
	}
	defer secretmem.Zero(keyBytes)
	attachmentKey := ports.AttachmentKey{Bytes: keyBytes}

	wrappedKey, err := s.crypto.WrapAttachmentKey(ctx, s.userKey, attachmentKey)
	if err != nil {
		return Attachment{}, err
	}

	return s.Upload(ctx, UploadInput{
		CipherID:      cipherID,
		FileName:      fileName,
		Size:          size,
		Plaintext:     plaintext,
		AttachmentKey: attachmentKey,
		WrappedKey:    wrappedKey,
	})
}

// DownloadByID fetches attachment metadata, downloads the encrypted content,
// and decrypts it into dst. Returns KindLocked when the service is locked.
func (s *Service) DownloadByID(ctx context.Context, cipherID, attachmentID string, dst io.Writer) error {
	if s.locked {
		return &errors.Error{Kind: errors.KindLocked, Op: "attachments.Service.DownloadByID", Message: "service is locked"}
	}

	meta, err := s.api.GetAttachment(ctx, cipherID, attachmentID)
	if err != nil {
		return err
	}

	reader, err := s.api.DownloadAttachment(ctx, meta.URL)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	return s.Download(ctx, meta, reader, dst)
}
