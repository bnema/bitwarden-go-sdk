package crypto

import (
	"fmt"

	"github.com/bnema/bitwarden-go-sdk/internal/core/errors"
	"github.com/bnema/bitwarden-go-sdk/internal/ports"
)

func encryptCipherString(key []byte, plaintext string) (string, error) {
	encrypted, err := encryptType2(key, plaintext)
	if err != nil {
		return "", &errors.Error{Kind: errors.KindCrypto, Op: "crypto.EncryptCipher", Code: "encryption_failed", Message: "failed to encrypt cipher field"}
	}
	return encrypted, nil
}

func decryptCipherString(key []byte, encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}
	decrypted, err := decryptCipherEncString(key, encrypted)
	if err != nil {
		return "", &errors.Error{Kind: errors.KindCrypto, Op: "crypto.DecryptCipher", Code: "decryption_failed", Message: "failed to decrypt cipher field", Cause: err}
	}
	return decrypted, nil
}

func decryptCipherEncString(key []byte, encrypted string) (string, error) {
	enc, err := ParseEncString(encrypted)
	if err != nil {
		return "", err
	}

	switch enc.Type {
	case 0:
		if len(key) != 64 {
			return "", fmt.Errorf("user key must be 64 bytes")
		}
		plaintext, err := aes256cbcDecrypt(key[:32], enc.IV, enc.Data)
		if err != nil {
			return "", err
		}
		unpadded, err := pkcs7Unpad(plaintext)
		if err != nil {
			return "", err
		}
		return string(unpadded), nil
	case 2:
		return decryptType2(key, encrypted)
	default:
		return "", fmt.Errorf("unsupported enc string type %d", enc.Type)
	}
}

func encryptIdentity(key []byte, src *ports.IdentityCipher, dst *ports.EncryptedIdentityCipher) error {
	var err error
	if dst.Title, err = encryptCipherString(key, src.Title); err != nil {
		return err
	}
	if dst.FirstName, err = encryptCipherString(key, src.FirstName); err != nil {
		return err
	}
	if dst.MiddleName, err = encryptCipherString(key, src.MiddleName); err != nil {
		return err
	}
	if dst.LastName, err = encryptCipherString(key, src.LastName); err != nil {
		return err
	}
	if dst.Address1, err = encryptCipherString(key, src.Address1); err != nil {
		return err
	}
	if dst.Address2, err = encryptCipherString(key, src.Address2); err != nil {
		return err
	}
	if dst.Address3, err = encryptCipherString(key, src.Address3); err != nil {
		return err
	}
	if dst.City, err = encryptCipherString(key, src.City); err != nil {
		return err
	}
	if dst.State, err = encryptCipherString(key, src.State); err != nil {
		return err
	}
	if dst.PostalCode, err = encryptCipherString(key, src.PostalCode); err != nil {
		return err
	}
	if dst.Country, err = encryptCipherString(key, src.Country); err != nil {
		return err
	}
	if dst.Company, err = encryptCipherString(key, src.Company); err != nil {
		return err
	}
	if dst.Email, err = encryptCipherString(key, src.Email); err != nil {
		return err
	}
	if dst.Phone, err = encryptCipherString(key, src.Phone); err != nil {
		return err
	}
	if dst.SSN, err = encryptCipherString(key, src.SSN); err != nil {
		return err
	}
	if dst.Username, err = encryptCipherString(key, src.Username); err != nil {
		return err
	}
	if dst.PassportNumber, err = encryptCipherString(key, src.PassportNumber); err != nil {
		return err
	}
	if dst.LicenseNumber, err = encryptCipherString(key, src.LicenseNumber); err != nil {
		return err
	}
	return nil
}

func decryptIdentity(key []byte, src *ports.EncryptedIdentityCipher, dst *ports.IdentityCipher) error {
	var err error
	if dst.Title, err = decryptCipherString(key, src.Title); err != nil {
		return err
	}
	if dst.FirstName, err = decryptCipherString(key, src.FirstName); err != nil {
		return err
	}
	if dst.MiddleName, err = decryptCipherString(key, src.MiddleName); err != nil {
		return err
	}
	if dst.LastName, err = decryptCipherString(key, src.LastName); err != nil {
		return err
	}
	if dst.Address1, err = decryptCipherString(key, src.Address1); err != nil {
		return err
	}
	if dst.Address2, err = decryptCipherString(key, src.Address2); err != nil {
		return err
	}
	if dst.Address3, err = decryptCipherString(key, src.Address3); err != nil {
		return err
	}
	if dst.City, err = decryptCipherString(key, src.City); err != nil {
		return err
	}
	if dst.State, err = decryptCipherString(key, src.State); err != nil {
		return err
	}
	if dst.PostalCode, err = decryptCipherString(key, src.PostalCode); err != nil {
		return err
	}
	if dst.Country, err = decryptCipherString(key, src.Country); err != nil {
		return err
	}
	if dst.Company, err = decryptCipherString(key, src.Company); err != nil {
		return err
	}
	if dst.Email, err = decryptCipherString(key, src.Email); err != nil {
		return err
	}
	if dst.Phone, err = decryptCipherString(key, src.Phone); err != nil {
		return err
	}
	if dst.SSN, err = decryptCipherString(key, src.SSN); err != nil {
		return err
	}
	if dst.Username, err = decryptCipherString(key, src.Username); err != nil {
		return err
	}
	if dst.PassportNumber, err = decryptCipherString(key, src.PassportNumber); err != nil {
		return err
	}
	if dst.LicenseNumber, err = decryptCipherString(key, src.LicenseNumber); err != nil {
		return err
	}
	return nil
}
