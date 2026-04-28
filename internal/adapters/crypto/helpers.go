package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// stretchKey derives enc (32) and mac (32) sub-keys from a 32-byte master key
// using RFC5869 HKDF-Expand with the master key as the PRK and info "enc" / "mac".
func stretchKey(masterKey []byte) (encKey, macKey [32]byte) {
	hkdfExpandSHA256(encKey[:], masterKey, []byte("enc"))
	hkdfExpandSHA256(macKey[:], masterKey, []byte("mac"))
	return
}

func hkdfExpandSHA256(out, prk, info []byte) {
	h := hmac.New(sha256.New, prk)
	var previous []byte
	var offset byte
	for counter := byte(1); offset < byte(len(out)); counter++ {
		h.Reset()
		h.Write(previous)
		h.Write(info)
		h.Write([]byte{counter})
		previous = h.Sum(nil)
		offset += byte(copy(out[offset:], previous))
	}
}

// parseEncString parses a Bitwarden EncString of type 0 or 2.
// Returns type, iv, ciphertext, mac (nil for type 0), error.
func parseEncString(raw string) (encType int, iv, ct, mac []byte, err error) {
	enc, err := ParseEncString(raw)
	if err != nil {
		return 0, nil, nil, nil, err
	}
	switch enc.Type {
	case 0:
		return 0, enc.IV, enc.Data, nil, nil
	case 2:
		return 2, enc.IV, enc.Data, enc.MAC, nil
	default:
		return 0, nil, nil, nil, fmt.Errorf("unsupported enc string type for user key: %d", enc.Type)
	}
}

// computeMac computes HMAC-SHA256(key, iv || ciphertext).
func computeMac(macKey, iv, ciphertext []byte) []byte {
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ciphertext)
	return h.Sum(nil)
}

// constantTimeEq returns true if a and b are equal in constant time.
func constantTimeEq(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS7.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

// pkcs7Unpad removes PKCS7 padding.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid padding: empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > len(data) || padLen > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}

// aes256cbcDecrypt decrypts with AES-256-CBC. Caller must unpad.
func aes256cbcDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length")
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid iv length")
	}
	if len(ciphertext)%aes.BlockSize != 0 || len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext not block-aligned")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

// encryptType2 encrypts plaintext as an EncString type 2 using the given 64-byte
// user key (encKey = first 32 bytes, macKey = next 32 bytes). Returns the
// serialized EncString.
func encryptType2(userKey []byte, plaintext string) (string, error) {
	if len(userKey) != 64 {
		return "", fmt.Errorf("user key must be 64 bytes")
	}
	encKey := userKey[:32]
	macKey := userKey[32:64]

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("iv generation failed: %w", err)
	}

	ct, err := aes256cbcEncrypt(encKey, iv, []byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("aes-cbc encrypt failed: %w", err)
	}

	mac := computeMac(macKey, iv, ct)

	encStr := EncString{Type: 2, IV: iv, Data: ct, MAC: mac}
	return encStr.String()
}

// decryptType2 decrypts a serialized type 2 EncString using the given 64-byte
// user key. Returns the plaintext.
func decryptType2(userKey []byte, encrypted string) (string, error) {
	if len(userKey) != 64 {
		return "", fmt.Errorf("user key must be 64 bytes")
	}

	enc, err := ParseEncString(encrypted)
	if err != nil {
		return "", fmt.Errorf("parse failed: %w", err)
	}
	if enc.Type != 2 {
		return "", fmt.Errorf("expected enc string type 2, got %d", enc.Type)
	}

	encKey := userKey[:32]
	macKey := userKey[32:64]

	expectedMAC := computeMac(macKey, enc.IV, enc.Data)
	if !constantTimeEq(expectedMAC, enc.MAC) {
		return "", fmt.Errorf("MAC verification failed")
	}

	plaintext, err := aes256cbcDecrypt(encKey, enc.IV, enc.Data)
	if err != nil {
		return "", fmt.Errorf("aes-cbc decrypt failed: %w", err)
	}

	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return "", fmt.Errorf("unpad failed: %w", err)
	}

	return string(unpadded), nil
}

// aes256cbcEncrypt encrypts with AES-256-CBC. Returns padded ciphertext.
func aes256cbcEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length")
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid iv length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}
