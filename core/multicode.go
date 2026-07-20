package core

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"

	mh "github.com/multiformats/go-multihash"
	"golang.org/x/crypto/sha3"
	"lukechampine.com/blake3"
)

// Multicodec codes used by sesam.
// See https://github.com/multiformats/multicodec/blob/master/table.csv
const (
	MhSHA3_256    = mh.SHA3_256    // 0x16 - SHA3-256 hash digests
	MhBlake3      = mh.BLAKE3      // 0x1e - BLAKE3 hash digests
	MhEd25519Pub  = uint64(0xed)   // ed25519-pub key
	MhEd25519Priv = uint64(0x1300) // ed25519-priv key
	MhEdDSA       = uint64(0xd0ed) // EdDSA signature
)

// defaultHashCode is the algorithm used for all newly written hashes.
const defaultHashCode = MhBlake3

// blake3DigestSize is the BLAKE3 output size (256 bit) we use. It matches
// SHA3-256 so digests stay interchangeable in the fixed-layout signed payloads.
const blake3DigestSize = 32

// newHasher returns a constructor for the hash identified by a multicodec code.
// This is the single place mapping codes to implementations; every caller
// builds its hasher through it instead of hardcoding an algorithm.
func newHasher(code uint64) (func() hash.Hash, error) {
	switch code {
	case MhSHA3_256:
		return sha3.New256, nil
	case MhBlake3:
		return func() hash.Hash {
			return blake3.New(blake3DigestSize, nil)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported hash multicodec 0x%x", code)
	}
}

// hasherForStored returns the hash constructor and multicodec a stored multicode
// value was produced with.
func hasherForStored(stored string) (func() hash.Hash, uint64, error) {
	_, code, err := multicodeDecode(stored)
	if err != nil {
		return nil, 0, err
	}

	newHash, err := newHasher(code)
	if err != nil {
		return nil, 0, err
	}

	return newHash, code, nil
}

// MulticodeEncode wraps raw bytes in a multihash envelope and returns the
// base64 (standard, padded) representation.
func MulticodeEncode(digest []byte, code uint64) string {
	encoded, _ := mh.Encode(digest, code)
	return base64.StdEncoding.EncodeToString(encoded)
}

// MulticodeDecode is the inverse of MhEncode: base64-decode, then multihash-decode.
// It returns the raw digest and the hash code so callers can verify the algorithm.
func multicodeDecode(s string) (digest []byte, code uint64, err error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, 0, fmt.Errorf("base64 decode: %w", err)
	}

	decoded, err := mh.Decode(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("multihash decode: %w", err)
	}

	return decoded.Digest, decoded.Code, nil
}

// hashData hashes data with the default algorithm and returns a multicode string.
func hashData(data []byte) string {
	newHash, err := newHasher(defaultHashCode)
	if err != nil {
		// defaultHashCode is a constant we always support.
		panic(fmt.Sprintf("default hash code unsupported: %v", err))
	}

	h := newHash()
	_, _ = h.Write(data)
	return MulticodeEncode(h.Sum(nil), defaultHashCode)
}

// hashedDataEqual reports whether data hashes to the stored multicode digest, using
// whichever algorithm the stored value declares.
func hashedDataEqual(stored string, data []byte) (bool, error) {
	_, code, err := multicodeDecode(stored)
	if err != nil {
		return false, err
	}

	newHash, err := newHasher(code)
	if err != nil {
		return false, err
	}

	h := newHash()
	_, _ = h.Write(data)
	return hashEqual(stored, code, h.Sum(nil))
}

// hashEqual compares an already-computed digest against a stored multicode
// value, requiring the stored value to use `code`.
func hashEqual(stored string, code uint64, digest []byte) (bool, error) {
	want, gotCode, err := multicodeDecode(stored)
	if err != nil {
		return false, err
	}

	if gotCode != code {
		return false, fmt.Errorf("hash codec mismatch: want 0x%x, got 0x%x", code, gotCode)
	}

	return subtle.ConstantTimeCompare(digest, want) == 1, nil
}
