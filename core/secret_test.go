package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
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

func testSecret(t *testing.T, mgr *SecretManager, path, content string) *secret {
	t.Helper()
	writeSecret(t, mgr.SesamDir, path, content)
	return &secret{
		Mgr:          mgr,
		RevealedPath: path,
		Recipients:   mgr.Keyring.Recipients([]string{mgr.Signer.UserName()}),
	}
}

func TestSealAndReveal(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/db_password", "super-secret-password-123")

	sig, err := secret.Seal("testuser")
	require.NoError(t, err)
	require.Equal(t, "secrets/db_password", sig.RevealedPath)
	require.Equal(t, "testuser", sig.SealedBy)
	require.NotEmpty(t, sig.Hash)
	require.NotEmpty(t, sig.Signature)

	// Check files were created.
	require.FileExists(t, mgr.cryptPath("secrets/db_password"))
	require.FileExists(t, signaturePath(mgr.SesamDir, "secrets/db_password"))

	// Remove plaintext, then reveal and compare.
	plainPath := filepath.Join(mgr.SesamDir, "secrets/db_password")
	os.Remove(plainPath)

	require.NoError(t, secret.Reveal())

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

			_, err := secret.Seal("testuser")
			require.NoError(t, err)

			os.Remove(filepath.Join(mgr.SesamDir, tc.path))

			require.NoError(t, secret.Reveal())

			got, _ := os.ReadFile(filepath.Join(mgr.SesamDir, tc.path))
			require.Equal(t, tc.content, string(got))
		})
	}
}

func TestSealCreatesSignatureFile(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "config/api_key", "key-abc-456")

	_, err := secret.Seal("testuser")
	require.NoError(t, err)

	sigDesc, err := readStoredSignature(mgr.SesamDir, "config/api_key")
	require.NoError(t, err)
	require.Equal(t, "config/api_key", sigDesc.RevealedPath)
	require.Equal(t, "testuser", sigDesc.SealedBy)
}

func TestRevealDetectsCorruptedCiphertext(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/token", "original-token")

	_, err := secret.Seal("testuser")
	require.NoError(t, err)

	// Corrupt the .age file contents.
	os.WriteFile(mgr.cryptPath("secrets/token"), []byte("corrupted-ciphertext"), 0o600)

	err = secret.Reveal()
	require.Error(t, err, "reveal should detect corrupted ciphertext")
}

func TestRevealDetectsTruncatedCiphertext(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/trunc", "some-data")

	_, err := secret.Seal("testuser")
	require.NoError(t, err)

	// Truncate the .age file to half its size.
	agePath := mgr.cryptPath("secrets/trunc")
	data, _ := os.ReadFile(agePath)
	os.WriteFile(agePath, data[:len(data)/2], 0o600)

	err = secret.Reveal()
	require.Error(t, err, "reveal should detect truncated ciphertext")
}

func TestRevealDetectsBadSignature(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/cert", "cert-data")

	_, err := secret.Seal("testuser")
	require.NoError(t, err)

	// Replace keyring with a different signing key.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	mgr.Keyring = EmptyKeyring()
	mgr.Keyring.AddSignPubKey("testuser", otherPub)

	err = secret.Reveal()
	require.Error(t, err, "reveal should detect signature from wrong key")
}

func TestRevealDetectsWrongSigner(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/wrong-signer", "data")

	_, err := secret.Seal("testuser")
	require.NoError(t, err)

	// Add a second user and remove the original, so sealedBy doesn't match any key.
	mgr.Keyring = EmptyKeyring()
	other := newTestUser(t, "other")
	mgr.Keyring.AddSignPubKey("other", other.Signer.PublicKey())

	err = secret.Reveal()
	require.Error(t, err, "reveal should fail when sealed_by user has no matching key")
}

func TestSealMissingFile(t *testing.T) {
	mgr := testSecretManager(t)
	secret := &secret{
		Mgr:          mgr,
		RevealedPath: "does/not/exist",
		Recipients:   mgr.Keyring.Recipients([]string{"testuser"}),
	}

	_, err := secret.Seal("testuser")
	require.Error(t, err)
}

func TestRevealMissingAgeFile(t *testing.T) {
	mgr := testSecretManager(t)
	secret := &secret{
		Mgr:          mgr,
		RevealedPath: "does/not/exist",
		Recipients:   mgr.Keyring.Recipients([]string{"testuser"}),
	}

	err := secret.Reveal()
	require.Error(t, err)
}

func TestRevealMissingSigFile(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/nosig", "data")

	_, err := secret.Seal("testuser")
	require.NoError(t, err)

	// Remove only the .sig.json, keep the .age.
	os.Remove(signaturePath(mgr.SesamDir, "secrets/nosig"))

	err = secret.Reveal()
	require.Error(t, err, "reveal should fail when .sig.json is missing")
}

func TestSealRevealLargeFile(t *testing.T) {
	mgr := testSecretManager(t)
	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte(i % 256)
	}

	secret := testSecret(t, mgr, "secrets/large", string(data))

	_, err := secret.Seal("testuser")
	require.NoError(t, err)

	os.Remove(filepath.Join(mgr.SesamDir, "secrets/large"))
	require.NoError(t, secret.Reveal())

	got, _ := os.ReadFile(filepath.Join(mgr.SesamDir, "secrets/large"))
	require.Equal(t, data, got)
}

func TestSealDoesNotLeakFileDescriptors(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/fdleak", "fd-test")

	fdsBefore := countOpenFDs(t)

	for i := 0; i < 50; i++ {
		_, err := secret.Seal("testuser")
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

	_, err := secret.Seal("testuser")
	require.NoError(t, err)

	fdsBefore := countOpenFDs(t)

	for i := 0; i < 50; i++ {
		require.NoError(t, secret.Reveal())
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

	expected, err := secret.Seal("testuser")
	require.NoError(t, err)

	got, err := readStoredSignature(mgr.SesamDir, "secrets/roundtrip")
	require.NoError(t, err)
	require.Equal(t, expected.RevealedPath, got.RevealedPath)
	require.Equal(t, expected.Hash, got.Hash)
	require.Equal(t, expected.Signature, got.Signature)
	require.Equal(t, expected.SealedBy, got.SealedBy)
}
