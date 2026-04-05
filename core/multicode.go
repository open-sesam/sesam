package core

import (
	"encoding/base64"
	"fmt"

	mh "github.com/multiformats/go-multihash"
	"golang.org/x/crypto/sha3"
)

// Multicodec codes used by sesam.
// See https://github.com/multiformats/multicodec/blob/master/table.csv
const (
	MhSHA3_256    = mh.SHA3_256    // 0x16 - SHA3-256 hash digests
	MhEd25519Pub  = uint64(0xed)   // ed25519-pub key
	MhEd25519Priv = uint64(0x1300) // ed25519-priv key
	MhEdDSA       = uint64(0xd0ed) // EdDSA signature
)

// MulticodeEncode wraps raw bytes in a multihash envelope and returns the
// base64 (standard, padded) representation.
func MulticodeEncode(digest []byte, code uint64) string {
	encoded, _ := mh.Encode(digest, code)
	return base64.StdEncoding.EncodeToString(encoded)
}

// MulticodeDecode is the inverse of MhEncode: base64-decode, then multihash-decode.
// It returns the raw digest and the hash code so callers can verify the algorithm.
func MulticodeDecode(s string) (digest []byte, code uint64, err error) {
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

// Hash builds uses the default hash algorithm for `data` and returns a multicode encoded stirng.
func Hash(data []byte) string {
	h := sha3.New256()
	_, _ = h.Write(data)
	return MulticodeEncode(h.Sum(nil), MhSHA3_256)
}
