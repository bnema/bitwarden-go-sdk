package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"os"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

const (
	attachmentChunkSize       = 32 * 1024
	attachmentMemorySpoolSize = 1 << 20
	attachmentHeaderSize      = 1 + aes.BlockSize + macLength
)

// WrapAttachmentKey encrypts an attachment key (arbitrary bytes) as a type-2 EncString
// using the user key. The user key must be 64 bytes.
func (e *Engine) WrapAttachmentKey(ctx context.Context, key ports.UserKey, attachmentKey ports.AttachmentKey) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(key.Bytes) != 64 {
		return "", cryptoError(errors.KindValidation, "crypto.WrapAttachmentKey", "invalid_key_length", "user key must be 64 bytes")
	}
	wrapped, err := encryptType2(key.Bytes, string(attachmentKey.Bytes))
	if err != nil {
		return "", cryptoError(errors.KindCrypto, "crypto.WrapAttachmentKey", "encryption_failed", "failed to wrap attachment key")
	}
	return wrapped, nil
}

// DecryptAttachmentKey decrypts an encrypted attachment key using the user key.
func (e *Engine) DecryptAttachmentKey(ctx context.Context, key ports.UserKey, attachment ports.EncryptedAttachment) (ports.AttachmentKey, error) {
	if err := ctx.Err(); err != nil {
		return ports.AttachmentKey{}, err
	}
	if len(key.Bytes) != 64 {
		return ports.AttachmentKey{}, cryptoError(errors.KindValidation, "crypto.DecryptAttachmentKey", "invalid_key_length", "user key must be 64 bytes")
	}
	plaintext, err := decryptType2(key.Bytes, attachment.Key)
	if err != nil {
		return ports.AttachmentKey{}, cryptoError(errors.KindCrypto, "crypto.DecryptAttachmentKey", "decryption_failed", "failed to decrypt attachment key")
	}
	return ports.AttachmentKey{Bytes: []byte(plaintext)}, nil
}

// EncryptAttachment encrypts attachment content from src into dst using the
// Bitwarden type-2 binary buffer format: type || iv || mac || ciphertext.
func (e *Engine) EncryptAttachment(ctx context.Context, key ports.AttachmentKey, src io.Reader, dst io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(key.Bytes) != 64 {
		return cryptoError(errors.KindValidation, "crypto.EncryptAttachment", "invalid_key_length", "attachment key must be 64 bytes")
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return cryptoError(errors.KindCrypto, "crypto.EncryptAttachment", "iv_generation_failed", "failed to generate attachment IV")
	}

	spool, err := newAttachmentSpool()
	if err != nil {
		return err
	}
	defer func() { _ = spool.Close() }()

	mac := hmac.New(sha256.New, key.Bytes[32:])
	_, _ = mac.Write(iv)
	err = encryptAttachmentCiphertext(ctx, key.Bytes[:32], iv, src, spool, mac)
	if closeErr := closeIfCloser(src); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := spool.Rewind(); err != nil {
		return err
	}

	if _, err = dst.Write([]byte{2}); err != nil {
		return err
	}
	if _, err = dst.Write(iv); err != nil {
		return err
	}
	if _, err = dst.Write(mac.Sum(nil)); err != nil {
		return err
	}
	if _, err = io.Copy(dst, spool); err != nil {
		return err
	}
	if closeErr := closeIfCloser(dst); closeErr != nil {
		return closeErr
	}
	return nil
}

// DecryptAttachment decrypts attachment content from src into dst after MAC
// verification. It writes no plaintext unless authentication succeeds.
func (e *Engine) DecryptAttachment(ctx context.Context, key ports.AttachmentKey, src io.Reader, dst io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(key.Bytes) != 64 {
		return cryptoError(errors.KindValidation, "crypto.DecryptAttachment", "invalid_key_length", "attachment key must be 64 bytes")
	}

	header := make([]byte, attachmentHeaderSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return cryptoError(errors.KindCrypto, "crypto.DecryptAttachment", "malformed_attachment", "encrypted attachment content is malformed")
	}
	if header[0] != 2 {
		return cryptoError(errors.KindCrypto, "crypto.DecryptAttachment", "unsupported_type", "encrypted attachment content type is unsupported")
	}
	iv := header[1 : 1+aes.BlockSize]
	gotMAC := header[1+aes.BlockSize:]

	spool, err := newAttachmentSpool()
	if err != nil {
		return err
	}
	defer func() { _ = spool.Close() }()

	mac := hmac.New(sha256.New, key.Bytes[32:])
	_, _ = mac.Write(iv)
	ciphertextLen, err := copyAttachmentCiphertext(ctx, src, spool, mac)
	if closeErr := closeIfCloser(src); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if ciphertextLen == 0 || ciphertextLen%aes.BlockSize != 0 {
		return cryptoError(errors.KindCrypto, "crypto.DecryptAttachment", "malformed_attachment", "encrypted attachment content is malformed")
	}
	if !constantTimeEq(mac.Sum(nil), gotMAC) {
		return cryptoError(errors.KindCrypto, "crypto.DecryptAttachment", "mac_mismatch", "attachment MAC verification failed")
	}
	if err := spool.Rewind(); err != nil {
		return err
	}
	if err := decryptAttachmentCiphertext(ctx, key.Bytes[:32], iv, spool, dst); err != nil {
		return err
	}
	if closeErr := closeIfCloser(dst); closeErr != nil {
		return closeErr
	}
	return nil
}

func encryptAttachmentCiphertext(ctx context.Context, key, iv []byte, src io.Reader, dst io.Writer, mac io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return cryptoError(errors.KindCrypto, "crypto.EncryptAttachment", "encryption_failed", "failed to encrypt attachment content")
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	readBuf := make([]byte, attachmentChunkSize)
	pending := make([]byte, 0, aes.BlockSize+attachmentChunkSize)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := src.Read(readBuf)
		if n > 0 {
			pending = append(pending, readBuf[:n]...)
			completeLen := len(pending) - (len(pending) % aes.BlockSize)
			if readErr == io.EOF {
				completeLen = 0
			}
			if completeLen > 0 {
				out := make([]byte, completeLen)
				mode.CryptBlocks(out, pending[:completeLen])
				if _, err := mac.Write(out); err != nil {
					return err
				}
				if _, err := dst.Write(out); err != nil {
					return err
				}
				copy(pending, pending[completeLen:])
				pending = pending[:len(pending)-completeLen]
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return readErr
			}
			finalBlock := pkcs7Pad(pending, aes.BlockSize)
			out := make([]byte, len(finalBlock))
			mode.CryptBlocks(out, finalBlock)
			if _, err := mac.Write(out); err != nil {
				return err
			}
			_, err := dst.Write(out)
			return err
		}
	}
}

func copyAttachmentCiphertext(ctx context.Context, src io.Reader, dst io.Writer, mac io.Writer) (int64, error) {
	buf := make([]byte, attachmentChunkSize)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, writeErr := mac.Write(chunk); writeErr != nil {
				return total, writeErr
			}
			if _, writeErr := dst.Write(chunk); writeErr != nil {
				return total, writeErr
			}
			total += int64(n)
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

func decryptAttachmentCiphertext(ctx context.Context, key, iv []byte, src io.Reader, dst io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return cryptoError(errors.KindCrypto, "crypto.DecryptAttachment", "decryption_failed", "failed to decrypt attachment content")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	readBuf := make([]byte, attachmentChunkSize)
	pending := make([]byte, 0, aes.BlockSize+attachmentChunkSize)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := src.Read(readBuf)
		if n > 0 {
			pending = append(pending, readBuf[:n]...)
			if len(pending) > aes.BlockSize {
				completeLen := len(pending) - aes.BlockSize
				completeLen -= completeLen % aes.BlockSize
				if completeLen > 0 {
					out := make([]byte, completeLen)
					mode.CryptBlocks(out, pending[:completeLen])
					if _, err := dst.Write(out); err != nil {
						return err
					}
					copy(pending, pending[completeLen:])
					pending = pending[:len(pending)-completeLen]
				}
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return readErr
			}
			if len(pending) == 0 || len(pending)%aes.BlockSize != 0 {
				return cryptoError(errors.KindCrypto, "crypto.DecryptAttachment", "malformed_attachment", "encrypted attachment content is malformed")
			}
			finalPlaintext := make([]byte, len(pending))
			mode.CryptBlocks(finalPlaintext, pending)
			unpadded, err := pkcs7Unpad(finalPlaintext)
			if err != nil {
				return cryptoError(errors.KindCrypto, "crypto.DecryptAttachment", "invalid_padding", "attachment padding invalid")
			}
			_, err = dst.Write(unpadded)
			return err
		}
	}
}

func closeIfCloser(v any) error {
	closer, ok := v.(io.Closer)
	if !ok {
		return nil
	}
	return closer.Close()
}

func cryptoError(kind errors.Kind, op, code, message string) error {
	return &errors.Error{Kind: kind, Op: op, Code: code, Message: message}
}

type attachmentSpool struct {
	buf      bytes.Buffer
	file     *os.File
	path     string
	size     int64
	readFrom io.Reader
}

func newAttachmentSpool() (*attachmentSpool, error) { return &attachmentSpool{}, nil }

func (s *attachmentSpool) Write(p []byte) (int, error) {
	if s.file == nil && s.size+int64(len(p)) > attachmentMemorySpoolSize {
		file, err := os.CreateTemp("", "bitwarden-go-sdk-attachment-*")
		if err != nil {
			return 0, err
		}
		s.file = file
		s.path = file.Name()
		if _, err := s.buf.WriteTo(file); err != nil {
			return 0, err
		}
	}
	var n int
	var err error
	if s.file != nil {
		n, err = s.file.Write(p)
	} else {
		n, err = s.buf.Write(p)
	}
	s.size += int64(n)
	return n, err
}

func (s *attachmentSpool) Read(p []byte) (int, error) {
	if s.readFrom == nil {
		s.readFrom = bytes.NewReader(s.buf.Bytes())
	}
	return s.readFrom.Read(p)
}

func (s *attachmentSpool) Rewind() error {
	if s.file != nil {
		if _, err := s.file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		s.readFrom = s.file
		return nil
	}
	s.readFrom = bytes.NewReader(s.buf.Bytes())
	return nil
}

func (s *attachmentSpool) Close() error {
	var err error
	if s.file != nil {
		err = s.file.Close()
		if removeErr := os.Remove(s.path); err == nil && removeErr != nil && !os.IsNotExist(removeErr) {
			err = removeErr
		}
	}
	return err
}

var _ interface {
	WrapAttachmentKey(ctx context.Context, key ports.UserKey, attachmentKey ports.AttachmentKey) (string, error)
	DecryptAttachmentKey(ctx context.Context, key ports.UserKey, attachment ports.EncryptedAttachment) (ports.AttachmentKey, error)
	EncryptAttachment(ctx context.Context, key ports.AttachmentKey, src io.Reader, dst io.Writer) error
	DecryptAttachment(ctx context.Context, key ports.AttachmentKey, src io.Reader, dst io.Writer) error
} = (*Engine)(nil)
