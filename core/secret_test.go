package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func testSecretManager(t *testing.T) *SecretManager {
	t.Helper()
	sesamDir := testRepo(t)
	user := newTestUser(t, "testuser")
	kr := testKeyring(t, user)

	return &SecretManager{
		SesamDir:   sesamDir,
		Identities: Identities{user.Identity},
		Signer:     user.Signer,
		Keyring:    kr,
		State: &VerifiedState{
			Users: []VerifiedUser{{
				Name:   user.Name,
				Groups: []string{"admin"},
			}},
		},
	}
}

// testSecret writes a plaintext file and registers it in the verified state
// so reveal-time authorization checks pass for the default test user (admin).
// It returns the revealed path, which seal/reveal helpers take directly.
func testSecret(t *testing.T, mgr *SecretManager, path, content string) string {
	t.Helper()
	writeSecret(t, mgr.SesamDir, path, content)

	if mgr.State != nil {
		mgr.State.Secrets = append(mgr.State.Secrets, VerifiedSecret{
			RevealedPath: path,
			AccessGroups: []string{"admin"},
		})
	}

	return path
}

func TestSealAndReveal(t *testing.T) {
	mgr := testSecretManager(t)
	path := testSecret(t, mgr, "secrets/db_password", "super-secret-password-123")

	sig, err := sealSecret(mgr, path, mgr.recipientsFor(path), mgr.cryptPath(path), "testuser")
	require.NoError(t, err)
	require.Equal(t, "secrets/db_password", sig.RevealedPath)
	require.Equal(t, "testuser", sig.SealedBy)
	require.NotEmpty(t, sig.CipherTextHash)
	require.NotEmpty(t, sig.Signature)

	// Check file was created.
	require.FileExists(t, mgr.cryptPath("secrets/db_password"))

	// Remove plaintext, then reveal and compare.
	plainPath := filepath.Join(mgr.SesamDir, "secrets/db_password")
	os.Remove(plainPath)

	require.NoError(t, revealSecret(mgr, path))

	got, _ := os.ReadFile(plainPath)
	require.Equal(t, "super-secret-password-123", string(got))
}

func TestSealRevealTableDriven(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		content string
	}{
		{"empty file", "secrets/empty", ""},
		{"short secret", "secrets/short", "pw"},
		{"with newlines", "secrets/multi", "line1\nline2\nline3"},
		{"binary-ish", "secrets/bin", string([]byte{0, 1, 2, 255, 254})},
		{"nested path", "deep/nested/dir/secret", "nested-content"},
		{"unicode", "secrets/unicode", "пароль 密码 パスワード"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := testSecretManager(t)
			secret := testSecret(t, mgr, tc.path, tc.content)

			_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
			require.NoError(t, err)

			os.Remove(filepath.Join(mgr.SesamDir, tc.path))

			require.NoError(t, revealSecret(mgr, secret))

			got, _ := os.ReadFile(filepath.Join(mgr.SesamDir, tc.path))
			require.Equal(t, tc.content, string(got))
		})
	}
}

func TestSealCreatesSignatureFile(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "config/api_key", "key-abc-456")

	_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	sigs, err := readAllSignatures(mgr.SesamDir)
	require.NoError(t, err)
	require.Len(t, sigs, 1)

	sigDesc := sigs[0]
	require.NoError(t, err)
	require.Equal(t, "config/api_key", sigDesc.RevealedPath)
	require.Equal(t, "testuser", sigDesc.SealedBy)
}

func TestRevealDetectsCorruptedCiphertext(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/token", "original-token")

	_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	// Corrupt the .sesam file contents.
	os.WriteFile(mgr.cryptPath("secrets/token"), []byte("corrupted-ciphertext"), 0o600)

	err = revealSecret(mgr, secret)
	require.Error(t, err, "reveal should detect corrupted ciphertext")
}

func TestRevealDetectsTruncatedCiphertext(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/trunc", "some-data")

	_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	// Truncate the .age file to half its size.
	agePath := mgr.cryptPath("secrets/trunc")
	data, _ := os.ReadFile(agePath)
	os.WriteFile(agePath, data[:len(data)/2], 0o600)

	err = revealSecret(mgr, secret)
	require.Error(t, err, "reveal should detect truncated ciphertext")
}

func TestRevealDetectsBadSignature(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/cert", "cert-data")

	_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	// Replace keyring with a different signing key.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	mgr.Keyring = EmptyKeyring()
	mgr.Keyring.SetSignPubKey("testuser", otherPub)

	err = revealSecret(mgr, secret)
	require.Error(t, err, "reveal should detect signature from wrong key")
}

func TestRevealDetectsWrongSigner(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/wrong-signer", "data")

	_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	// Add a second user and remove the original, so sealedBy doesn't match any key.
	mgr.Keyring = EmptyKeyring()
	other := newTestUser(t, "other")
	mgr.Keyring.SetSignPubKey("other", other.Signer.PublicKey())

	err = revealSecret(mgr, secret)
	require.Error(t, err, "reveal should fail when sealed_by user has no matching key")
}

func TestSealMissingFile(t *testing.T) {
	mgr := testSecretManager(t)
	path := "does/not/exist"
	recps := mgr.Keyring.Recipients([]string{"testuser"})

	_, err := sealSecret(mgr, path, recps, mgr.cryptPath(path), "testuser")
	require.Error(t, err)
}

func TestRevealMissingAgeFile(t *testing.T) {
	mgr := testSecretManager(t)

	err := revealSecret(mgr, "does/not/exist")
	require.Error(t, err)
}

func TestRevealMissingFooter(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/nofooter", "data")

	_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	// Overwrite the .sesam file with content that has no newline footer.
	os.WriteFile(mgr.cryptPath("secrets/nofooter"), []byte("no-footer-here"), 0o600)

	err = revealSecret(mgr, secret)
	require.Error(t, err, "reveal should fail when footer is missing")
}

func TestSealRevealLargeFile(t *testing.T) {
	mgr := testSecretManager(t)
	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte(i % 256)
	}

	secret := testSecret(t, mgr, "secrets/large", string(data))

	_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	os.Remove(filepath.Join(mgr.SesamDir, "secrets/large"))
	require.NoError(t, revealSecret(mgr, secret))

	got, _ := os.ReadFile(filepath.Join(mgr.SesamDir, "secrets/large"))
	require.Equal(t, data, got)
}

func TestSealDoesNotLeakFileDescriptors(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/fdleak", "fd-test")

	fdsBefore := countOpenFDs(t)

	for i := 0; i < 50; i++ {
		_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
		require.NoError(t, err)
	}

	// Force GC to close any lingering finalizers.
	runtime.GC()

	fdsAfter := countOpenFDs(t)
	// Allow some slack (runtime opens fds too), but not 50.
	require.Less(t, fdsAfter-fdsBefore, 10, "file descriptors leaked during Seal")
}

func TestRevealDoesNotLeakFileDescriptors(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/fdleak2", "fd-test")

	_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	fdsBefore := countOpenFDs(t)

	for i := 0; i < 50; i++ {
		require.NoError(t, revealSecret(mgr, secret))
	}

	runtime.GC()

	fdsAfter := countOpenFDs(t)
	require.Less(t, fdsAfter-fdsBefore, 10, "file descriptors leaked during Reveal")
}

// countOpenFDs returns the number of open file descriptors for the current process.
func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("cannot read /proc/self/fd (not Linux)")
	}
	return len(entries)
}

func TestReadStoredSignatureRoundtrip(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/roundtrip", "roundtrip-data")

	expected, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	sigs, err := readAllSignatures(mgr.SesamDir)
	require.NoError(t, err)
	require.Len(t, sigs, 1)

	got := sigs[0]
	require.Equal(t, expected.RevealedPath, got.RevealedPath)
	require.Equal(t, expected.CipherTextHash, got.CipherTextHash)
	require.Equal(t, expected.Signature, got.Signature)
	require.Equal(t, expected.SealedBy, got.SealedBy)
}

// Sanity: an authorized sealer's footer is accepted at reveal time.
// Guards against the new authorization layer false-positiving.
func TestRevealAcceptsAuthorizedSealer(t *testing.T) {
	mgr := testSecretManager(t)
	s := testSecret(t, mgr, "secrets/legit", "payload")

	_, err := sealSecret(mgr, s, mgr.recipientsFor(s), mgr.cryptPath(s), mgr.Signer.UserName())
	require.NoError(t, err)

	require.NoError(t, os.Remove(filepath.Join(mgr.SesamDir, s)))
	require.NoError(t, revealSecret(mgr, s))

	got, err := os.ReadFile(filepath.Join(mgr.SesamDir, s))
	require.NoError(t, err)
	require.Equal(t, "payload", string(got))
}

// Load-bearing test: the malicious-client scenario.
//
// Bob is in the audit log (in the "dev" group) but the access policy
// does not grant the "dev" group "secrets/admin-only". An honest client
// refuses to seal that path as bob, but a patched client could skip the
// policy guard. We simulate that by calling sealSecret directly with
// bob's signer. Admin's reveal must still reject the substituted footer
// even though bob's signature is cryptographically valid.
func TestRevealRejectsUnauthorizedSealer(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	bob := newTestUser(t, "bob")
	kr := testKeyring(t, admin, bob)

	state := &VerifiedState{
		Users: []VerifiedUser{
			{Name: "admin", Groups: []string{"admin"}},
			{Name: "bob", Groups: []string{"dev"}},
		},
		Secrets: []VerifiedSecret{
			{RevealedPath: "secrets/admin-only", AccessGroups: []string{"admin"}},
		},
	}

	adminMgr := &SecretManager{
		SesamDir:   sesamDir,
		Identities: Identities{admin.Identity},
		Signer:     admin.Signer,
		Keyring:    kr,
		State:      state,
	}

	// Step 1: admin legitimately seals the secret.
	writeSecret(t, sesamDir, "secrets/admin-only", "admin payload")
	adminRecps := kr.Recipients([]string{"admin"})
	_, err := sealSecret(adminMgr, "secrets/admin-only", adminRecps, adminMgr.cryptPath("secrets/admin-only"), "admin")
	require.NoError(t, err)

	// Step 2: bob substitutes content, bypassing the policy guard.
	// This is what a patched client would do. Deriving the content-hash
	// key requires decrypting the file, so bob can only seal a file he is
	// a recipient of - he seals to a set including himself (admin is kept
	// so admin can still reveal). Bob is a valid recipient here but still
	// not an authorized *sealer* of admin-only per the access policy.
	bobMgr := &SecretManager{
		SesamDir:   sesamDir,
		Identities: Identities{bob.Identity},
		Signer:     bob.Signer,
	}
	writeSecret(t, sesamDir, "secrets/admin-only", "bob's evil payload")
	bobRecps := kr.Recipients([]string{"admin", "bob"})
	_, err = sealSecret(bobMgr, "secrets/admin-only", bobRecps, adminMgr.cryptPath("secrets/admin-only"), "bob")
	require.NoError(t, err, "low-level sealSecret must accept this - the attacker bypassed the policy guard")

	// Step 3: admin reveals. The substituted footer is cryptographically
	// valid (real bob signature) but bob has no authority over admin-only.
	require.NoError(t, os.Remove(filepath.Join(sesamDir, "secrets/admin-only")))
	err = revealSecret(adminMgr, "secrets/admin-only")
	require.Error(t, err, "reveal must reject a footer signed by an unauthorized sealer")
	require.Contains(t, err.Error(), "not authorized")
	require.Contains(t, err.Error(), "bob")
}

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

	mac := keyContentHash(ageKey, h.Sum(nil))
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
