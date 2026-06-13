package core

import (
	"os"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/stretchr/testify/require"
)

// TestReadAgeEncryptionKey covers recovering the per-file age key from a
// sealed file's header - the key the content hash is derived from. It must
// be recoverable by a recipient, be deterministic for a given ciphertext,
// and fail for anyone who cannot decrypt the header.
func TestReadAgeEncryptionKey(t *testing.T) {
	mgr := testSecretManager(t)
	path := testSecret(t, mgr, "secrets/token", "top secret value")
	_, err := sealSecret(mgr, path, mgr.recipientsFor(path), mgr.cryptPath(path), "testuser")
	require.NoError(t, err)

	openSealed := func(t *testing.T) *os.File {
		t.Helper()
		//nolint:gosec
		fd, err := os.Open(mgr.cryptPath(path))
		require.NoError(t, err)
		t.Cleanup(func() { _ = fd.Close() })
		return fd
	}

	t.Run("recipient recovers the file key", func(t *testing.T) {
		key, err := readAgeEncryptionKey(openSealed(t), mgr.Identities.AgeIdentities())
		require.NoError(t, err)
		require.Len(t, key, 16) // age file key size
	})

	t.Run("same ciphertext yields the same key", func(t *testing.T) {
		k1, err := readAgeEncryptionKey(openSealed(t), mgr.Identities.AgeIdentities())
		require.NoError(t, err)
		k2, err := readAgeEncryptionKey(openSealed(t), mgr.Identities.AgeIdentities())
		require.NoError(t, err)
		require.Equal(t, k1, k2)
	})

	t.Run("non-recipient cannot recover the key", func(t *testing.T) {
		outsider := newTestUser(t, "outsider")
		_, err := readAgeEncryptionKey(openSealed(t), Identities{outsider.Identity}.AgeIdentities())
		require.Error(t, err)
	})

	t.Run("no identities is an error", func(t *testing.T) {
		_, err := readAgeEncryptionKey(openSealed(t), nil)
		require.Error(t, err)
	})
}

// recomputeContentHash reproduces what `sesam status` does to decide whether
// the working-tree plaintext still matches a sealed secret: read the sealed
// file's age key, hash plaintext+path, key it with the HKDF/HMAC derivation,
// and multicode-encode it the same way the footer stores it.
func recomputeContentHash(t *testing.T, mgr *SecretManager, path, plaintext string) string {
	t.Helper()
	//nolint:gosec
	fd, err := os.Open(mgr.cryptPath(path))
	require.NoError(t, err)
	defer func() { _ = fd.Close() }()

	ageKey, err := readAgeEncryptionKey(fd, mgr.Identities.AgeIdentities())
	require.NoError(t, err)

	h := sha3.New256()
	_, _ = h.Write([]byte(plaintext))
	_, _ = h.Write([]byte(path))

	mac, err := keyContentHash(ageKey, h.Sum(nil))
	require.NoError(t, err)
	return MulticodeEncode(mac, MhSHA3_256)
}

// TestContentHashStableForUnchangedContent pins the property `status` relies
// on: for a given sealed file, recomputing the keyed content hash from the
// unchanged plaintext reproduces the value stored in the footer, while any
// change to the plaintext produces a different hash (drift is detectable).
func TestContentHashStableForUnchangedContent(t *testing.T) {
	mgr := testSecretManager(t)
	const content = "the original content"
	path := testSecret(t, mgr, "secrets/token", content)

	footer, err := sealSecret(mgr, path, mgr.recipientsFor(path), mgr.cryptPath(path), "testuser")
	require.NoError(t, err)
	require.NotEmpty(t, footer.HMACContentHash)

	t.Run("unchanged plaintext reproduces the stored hash", func(t *testing.T) {
		require.Equal(t, footer.HMACContentHash, recomputeContentHash(t, mgr, path, content))
	})

	t.Run("changed plaintext yields a different hash", func(t *testing.T) {
		require.NotEqual(t, footer.HMACContentHash, recomputeContentHash(t, mgr, path, content+" tampered"))
	})
}

// TestContentHashChangesOnReseal documents the equality-hiding property:
// re-sealing identical plaintext must change the stored keyed hash, because
// age draws a fresh file key per encryption and the HMAC key is derived from
// it. This hides whether two seals (or two files) share a plaintext from
// anyone who cannot decrypt. `status` never relies on cross-seal stability -
// it always recomputes against the current seal (see
// TestContentHashStableForUnchangedContent).
func TestContentHashChangesOnReseal(t *testing.T) {
	mgr := testSecretManager(t)
	const content = "same content both times"
	path := testSecret(t, mgr, "secrets/token", content)

	first, err := sealSecret(mgr, path, mgr.recipientsFor(path), mgr.cryptPath(path), "testuser")
	require.NoError(t, err)

	// Plaintext on disk is unchanged; the re-seal produces a new ciphertext
	// and a fresh age file key.
	second, err := sealSecret(mgr, path, mgr.recipientsFor(path), mgr.cryptPath(path), "testuser")
	require.NoError(t, err)

	require.NotEqual(t, first.HMACContentHash, second.HMACContentHash,
		"fresh age file key per seal must change the keyed hash (equality hiding)")
}
