package crypto

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// EncString represents a Bitwarden symmetric encrypted string.
//
// Supported types:
//
//	0 - AES-256-CBC (legacy, unauthenticated)
//	2 - AES-256-CBC-HMAC-SHA256 (authenticated)
//	7 - COSE_Encrypt0
//
// Serialization format:
//
//	0.<iv_b64>|<data_b64>
//	2.<iv_b64>|<data_b64>|<mac_b64>
//	7.<data_b64>
type EncString struct {
	Type int
	IV   []byte
	Data []byte
	MAC  []byte
}

const (
	ivLength  = 16
	macLength = 32
)

// ParseEncString parses a serialized EncString in text format.
// Supported types are 0, 2, and 7.
func ParseEncString(raw string) (EncString, error) {
	// Must have exactly one dot separating type from data.
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 {
		return EncString{}, fmt.Errorf("malformed enc string: missing type prefix")
	}

	encType, err := strconv.Atoi(parts[0])
	if err != nil {
		return EncString{}, fmt.Errorf("malformed enc string: invalid type %q", parts[0])
	}

	dataParts := strings.Split(parts[1], "|")

	switch encType {
	case 0:
		if len(dataParts) != 2 {
			return EncString{}, fmt.Errorf("malformed enc string: type 0 expects 2 parts")
		}
		iv, err := base64.StdEncoding.DecodeString(dataParts[0])
		if err != nil {
			return EncString{}, fmt.Errorf("malformed enc string: invalid base64")
		}
		if len(iv) != ivLength {
			return EncString{}, fmt.Errorf("malformed enc string: invalid field length")
		}
		data, err := base64.StdEncoding.DecodeString(dataParts[1])
		if err != nil {
			return EncString{}, fmt.Errorf("malformed enc string: invalid base64")
		}
		return EncString{Type: 0, IV: iv, Data: data}, nil

	case 2:
		if len(dataParts) != 3 {
			return EncString{}, fmt.Errorf("malformed enc string: type 2 expects 3 parts")
		}
		iv, err := base64.StdEncoding.DecodeString(dataParts[0])
		if err != nil {
			return EncString{}, fmt.Errorf("malformed enc string: invalid base64")
		}
		if len(iv) != ivLength {
			return EncString{}, fmt.Errorf("malformed enc string: invalid field length")
		}
		data, err := base64.StdEncoding.DecodeString(dataParts[1])
		if err != nil {
			return EncString{}, fmt.Errorf("malformed enc string: invalid base64")
		}
		mac, err := base64.StdEncoding.DecodeString(dataParts[2])
		if err != nil {
			return EncString{}, fmt.Errorf("malformed enc string: invalid base64")
		}
		if len(mac) != macLength {
			return EncString{}, fmt.Errorf("malformed enc string: invalid field length")
		}
		return EncString{Type: 2, IV: iv, Data: data, MAC: mac}, nil

	case 7:
		if len(dataParts) != 1 {
			return EncString{}, fmt.Errorf("malformed enc string: type 7 expects 1 data part")
		}
		data, err := base64.StdEncoding.DecodeString(dataParts[0])
		if err != nil {
			return EncString{}, fmt.Errorf("malformed enc string: invalid base64")
		}
		return EncString{Type: 7, Data: data}, nil

	default:
		return EncString{}, fmt.Errorf("malformed enc string: unsupported type %d", encType)
	}
}

// String serializes an EncString to its text representation.
// The order is always iv|data|mac for type 2, matching Bitwarden specs.
func (e EncString) String() (string, error) {
	switch e.Type {
	case 0:
		if len(e.IV) != ivLength {
			return "", fmt.Errorf("cannot serialize type 0: IV length is %d, expected %d", len(e.IV), ivLength)
		}
		return "0." + base64.StdEncoding.EncodeToString(e.IV) + "|" + base64.StdEncoding.EncodeToString(e.Data), nil

	case 2:
		if len(e.IV) != ivLength {
			return "", fmt.Errorf("cannot serialize type 2: IV length is %d, expected %d", len(e.IV), ivLength)
		}
		if len(e.MAC) != macLength {
			return "", fmt.Errorf("cannot serialize type 2: MAC length is %d, expected %d", len(e.MAC), macLength)
		}
		return "2." +
			base64.StdEncoding.EncodeToString(e.IV) + "|" +
			base64.StdEncoding.EncodeToString(e.Data) + "|" +
			base64.StdEncoding.EncodeToString(e.MAC), nil

	case 7:
		return "7." + base64.StdEncoding.EncodeToString(e.Data), nil

	default:
		return "", fmt.Errorf("cannot serialize unsupported type %d", e.Type)
	}
}
