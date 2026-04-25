package core

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMulticodeRoundtrip(t *testing.T) {
	cases := []struct {
		name string
		code uint64
	}{
		{"SHA3-256", MhSHA3_256},
		{"EdDSA", MhEdDSA},
		{"Ed25519Pub", MhEd25519Pub},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("hello world")
			encoded := MulticodeEncode(data, tc.code)
			require.NotEmpty(t, encoded)

			decoded, code, err := multicodeDecode(encoded)
			require.NoError(t, err)
			require.Equal(t, tc.code, code)
			require.Equal(t, data, decoded)
		})
	}
}

func TestMulticodeDecodeNegative(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"invalid base64", "not-valid-base64!!!"},
		{"empty string", ""},
		{"invalid multihash (too short)", "AA=="},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := multicodeDecode(tc.input)
			require.Error(t, err)
		})
	}
}

func TestHashDeterministic(t *testing.T) {
	h1 := hashData([]byte("test"))
	h2 := hashData([]byte("test"))
	require.Equal(t, h1, h2, "same input should produce same hash")

	h3 := hashData([]byte("different"))
	require.NotEqual(t, h1, h3, "different input should produce different hash")
}

func TestHashEmpty(t *testing.T) {
	h := hashData([]byte{})
	require.NotEmpty(t, h, "empty input should still produce a hash")
}

func TestMulticodeEncodeDeterministic(t *testing.T) {
	data := []byte("deterministic-test")
	e1 := MulticodeEncode(data, MhSHA3_256)
	e2 := MulticodeEncode(data, MhSHA3_256)
	require.Equal(t, e1, e2)
}

func TestMulticodeEncodeDifferentCodes(t *testing.T) {
	data := []byte("same data")
	e1 := MulticodeEncode(data, MhSHA3_256)
	e2 := MulticodeEncode(data, MhEdDSA)
	require.NotEqual(t, e1, e2, "different codes should produce different encodings")
}
