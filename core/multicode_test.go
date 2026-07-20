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
		{"BLAKE3", MhBlake3},
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

// encodeHashWith hashes data with the given algorithm and returns the multicode
// string, mirroring what an object sealed with that algorithm would store.
func encodeHashWith(t *testing.T, code uint64, data []byte) string {
	t.Helper()
	newHash, err := newHasher(code)
	require.NoError(t, err)

	h := newHash()
	_, _ = h.Write(data)
	return MulticodeEncode(h.Sum(nil), code)
}

func TestNewHasher(t *testing.T) {
	for _, code := range []uint64{MhSHA3_256, MhBlake3} {
		newHash, err := newHasher(code)
		require.NoError(t, err)
		require.Equal(t, 32, newHash().Size())
	}

	_, err := newHasher(0xffff)
	require.Error(t, err)
}

func TestHasherForStored(t *testing.T) {
	for _, code := range []uint64{MhSHA3_256, MhBlake3} {
		stored := encodeHashWith(t, code, []byte("x"))
		newHash, gotCode, err := hasherForStored(stored)
		require.NoError(t, err)
		require.Equal(t, code, gotCode)
		require.Equal(t, 32, newHash().Size())
	}

	// A hash tagged with an algorithm we don't know is an error, not a guess.
	_, _, err := hasherForStored(MulticodeEncode([]byte("x"), MhEdDSA))
	require.Error(t, err)
}

func TestHashDataDefaultIsBlake3(t *testing.T) {
	_, code, err := multicodeDecode(hashData([]byte("payload")))
	require.NoError(t, err)
	require.Equal(t, uint64(MhBlake3), code)
}

// TestHashEqualReadsStoredAlgorithm is the core backwards-compat property: a
// stored SHA3-256 hash still verifies even though new hashes are BLAKE3, because
// hashEqual takes the algorithm from the stored value.
func TestHashEqualReadsStoredAlgorithm(t *testing.T) {
	data := []byte("audit-entry-bytes")

	for _, code := range []uint64{MhSHA3_256, MhBlake3} {
		stored := encodeHashWith(t, code, data)

		ok, err := hashedDataEqual(stored, data)
		require.NoError(t, err)
		require.True(t, ok, "code 0x%x should verify against its own data", code)

		ok, err = hashedDataEqual(stored, []byte("tampered"))
		require.NoError(t, err)
		require.False(t, ok, "code 0x%x must reject changed data", code)
	}

	// An unknown/unsupported hash codec is reported, not silently accepted.
	_, err := hashedDataEqual(MulticodeEncode([]byte("x"), MhEdDSA), data)
	require.Error(t, err)
}

func TestHashDigestEqual(t *testing.T) {
	data := []byte("ciphertext-stream")
	newHash, err := newHasher(MhBlake3)
	require.NoError(t, err)
	h := newHash()
	_, _ = h.Write(data)
	digest := h.Sum(nil)

	stored := MulticodeEncode(digest, MhBlake3)

	ok, err := hashEqual(stored, MhBlake3, digest)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = hashEqual(stored, MhBlake3, []byte("wrong-digest"))
	require.NoError(t, err)
	require.False(t, ok)

	// Declaring a different codec than the stored value is an error, not a
	// silent mismatch: it guards against footer-version / prefix disagreement.
	_, err = hashEqual(stored, MhSHA3_256, digest)
	require.Error(t, err)
}
