package crypto

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

type encStringVector struct {
	Name       string `json:"name"`
	Serialized string `json:"serialized"`
	Type       int    `json:"type"`
	IVLength   int    `json:"ivLength"`
	DataLength int    `json:"dataLength"`
	MACLength  int    `json:"macLength,omitempty"`
}

type encStringFixtures struct {
	ParseVectors []encStringVector `json:"parseVectors"`
}

func loadEncStringVectors(t *testing.T) []encStringVector {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/bitwarden/crypto/enc_string_vectors.json")
	require.NoError(t, err)
	var f encStringFixtures
	require.NoError(t, json.Unmarshal(data, &f))
	require.NotEmpty(t, f.ParseVectors)
	return f.ParseVectors
}

// ---------------------------------------------------------------------------
// Fixture-driven parse tests
// ---------------------------------------------------------------------------

func TestEncStringParseFixtureVectors(t *testing.T) {
	for _, vec := range loadEncStringVectors(t) {
		t.Run(vec.Name, func(t *testing.T) {
			enc, err := ParseEncString(vec.Serialized)
			require.NoError(t, err, "failed to parse valid enc string %q", vec.Serialized)

			assert.Equal(t, vec.Type, enc.Type, "type mismatch")
			assert.Len(t, enc.Data, vec.DataLength, "data length mismatch")

			if vec.IVLength > 0 {
				assert.Len(t, enc.IV, vec.IVLength, "iv length mismatch")
			}
			if vec.MACLength > 0 {
				assert.Len(t, enc.MAC, vec.MACLength, "mac length mismatch")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Roundtrip tests: parse -> serialize -> re-parse → stable
// ---------------------------------------------------------------------------

func TestEncStringRoundtripType0(t *testing.T) {
	// Type 0: 0.<iv_b64>|<data_b64>
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	data := []byte("test data for type 0")
	raw := "0." + base64.StdEncoding.EncodeToString(iv) + "|" + base64.StdEncoding.EncodeToString(data)

	enc, err := ParseEncString(raw)
	require.NoError(t, err)
	assert.Equal(t, 0, enc.Type)
	assert.Equal(t, iv, enc.IV)
	assert.Equal(t, data, enc.Data)
	assert.Nil(t, enc.MAC)

	serialized, err := enc.String()
	require.NoError(t, err)
	assert.Equal(t, raw, serialized)

	reparsed, err := ParseEncString(serialized)
	require.NoError(t, err)
	assert.Equal(t, enc, reparsed)
}

func TestEncStringRoundtripType2(t *testing.T) {
	// Type 2: 2.<iv_b64>|<data_b64>|<mac_b64>
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	data := []byte("test data for type 2")
	mac := make([]byte, 32)
	for i := range mac {
		mac[i] = byte((i + 1) % 256)
	}
	raw := "2." + base64.StdEncoding.EncodeToString(iv) +
		"|" + base64.StdEncoding.EncodeToString(data) +
		"|" + base64.StdEncoding.EncodeToString(mac)

	enc, err := ParseEncString(raw)
	require.NoError(t, err)
	assert.Equal(t, 2, enc.Type)
	assert.Equal(t, iv, enc.IV)
	assert.Equal(t, data, enc.Data)
	assert.Equal(t, mac, enc.MAC)

	serialized, err := enc.String()
	require.NoError(t, err)
	assert.Equal(t, raw, serialized)

	reparsed, err := ParseEncString(serialized)
	require.NoError(t, err)
	assert.Equal(t, enc, reparsed)
}

func TestEncStringRoundtripType7(t *testing.T) {
	// Type 7: 7.<data_b64>
	data := []byte("type 7 cose data")
	raw := "7." + base64.StdEncoding.EncodeToString(data)

	enc, err := ParseEncString(raw)
	require.NoError(t, err)
	assert.Equal(t, 7, enc.Type)
	assert.Equal(t, data, enc.Data)
	assert.Nil(t, enc.IV)
	assert.Nil(t, enc.MAC)

	serialized, err := enc.String()
	require.NoError(t, err)
	assert.Equal(t, raw, serialized)

	reparsed, err := ParseEncString(serialized)
	require.NoError(t, err)
	assert.Equal(t, enc, reparsed)
}

// ---------------------------------------------------------------------------
// Malformed input tests
// ---------------------------------------------------------------------------

func TestEncStringMalformedMissingDot(t *testing.T) {
	_, err := ParseEncString("no-dot-here")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed")
}

func TestEncStringMalformedUnsupportedType(t *testing.T) {
	// Type 1 is deprecated and not supported. 8/9/999 are also unsupported.
	for _, raw := range []string{
		"1.iv|data",
		"8.iv|data",
		"9.iv|data",
		"999.iv|data",
	} {
		_, err := ParseEncString(raw)
		require.Error(t, err, "expected error for %q", raw)
		assert.Contains(t, err.Error(), "unsupported", "raw=%q", raw)
	}
	// Non-numeric type prefix is a distinct error path.
	_, err := ParseEncString("abc.iv|data")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")
}

func TestEncStringMalformedWrongPartCount(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"type 0 with 1 part", "0.onlydata"},
		{"type 0 with 3 parts", "0.iv|data|extra"},
		{"type 2 with 2 parts", "2.iv|data"},
		{"type 2 with 4 parts", "2.iv|data|mac|extra"},
		{"type 7 with 2 parts", "7.data|extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseEncString(tt.raw)
			require.Error(t, err, "expected error for %q", tt.raw)
		})
	}
}

func TestEncStringMalformedBadBase64(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"type 0 bad iv base64", "0.!!!|AAAA"},
		{"type 0 bad data base64", "0.AAAAAAAAAAAAAAAAAAAAAA==|!!!|extra"},
		{"type 2 bad mac base64", "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAA|!!!"},
		{"type 7 bad data base64", "7.!!!"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseEncString(tt.raw)
			require.Error(t, err, "expected error for %q", tt.raw)
		})
	}
}

func TestEncStringMalformedIVLength(t *testing.T) {
	// IV must be exactly 16 bytes.
	shortIV := base64.StdEncoding.EncodeToString([]byte("short"))
	longIV := base64.StdEncoding.EncodeToString(make([]byte, 17))
	data := base64.StdEncoding.EncodeToString([]byte("data"))

	_, err := ParseEncString("0." + shortIV + "|" + data)
	require.Error(t, err)

	_, err = ParseEncString("0." + longIV + "|" + data)
	require.Error(t, err)

	mac := base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, err = ParseEncString("2." + shortIV + "|" + data + "|" + mac)
	require.Error(t, err)
}

func TestEncStringMalformedMACLength(t *testing.T) {
	// MAC must be exactly 32 bytes.
	iv := base64.StdEncoding.EncodeToString(make([]byte, 16))
	data := base64.StdEncoding.EncodeToString([]byte("data"))
	shortMAC := base64.StdEncoding.EncodeToString(make([]byte, 16))

	_, err := ParseEncString("2." + iv + "|" + data + "|" + shortMAC)
	require.Error(t, err)

	longMAC := base64.StdEncoding.EncodeToString(make([]byte, 33))
	_, err = ParseEncString("2." + iv + "|" + data + "|" + longMAC)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Serialization of a manually constructed EncString
// ---------------------------------------------------------------------------

func TestEncStringSerializeManuallyConstructed(t *testing.T) {
	iv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	mac := make([]byte, 32)
	for i := range mac {
		mac[i] = byte(i)
	}
	data := []byte("hello")

	enc := EncString{Type: 2, IV: iv, Data: data, MAC: mac}
	s, err := enc.String()
	require.NoError(t, err)
	expected := "2." + base64.StdEncoding.EncodeToString(iv) +
		"|" + base64.StdEncoding.EncodeToString(data) +
		"|" + base64.StdEncoding.EncodeToString(mac)
	assert.Equal(t, expected, s)
}

func TestEncStringRoundtripType7Empty(t *testing.T) {
	// "7." with empty data should roundtrip (matches Rust SDK behavior).
	raw := "7."
	enc, err := ParseEncString(raw)
	require.NoError(t, err)
	assert.Equal(t, 7, enc.Type)
	assert.Empty(t, enc.Data)

	serialized, err := enc.String()
	require.NoError(t, err)
	assert.Equal(t, "7.", serialized)

	reparsed, err := ParseEncString(serialized)
	require.NoError(t, err)
	assert.Equal(t, enc, reparsed)
}

func TestEncStringSerializeType7ManuallyConstructed(t *testing.T) {
	data := []byte("type 7 payload")
	enc := EncString{Type: 7, Data: data}
	s, err := enc.String()
	require.NoError(t, err)
	expected := "7." + base64.StdEncoding.EncodeToString(data)
	assert.Equal(t, expected, s)
}
