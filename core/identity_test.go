package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/plugin"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

// encryptedSSHKey returns a PEM-encoded ed25519 SSH private key locked with
// the given passphrase.
func encryptedSSHKey(t *testing.T, passphrase string) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	require.NoError(t, err)
	return pem.EncodeToMemory(block)
}

// mockPassphraseProvider serves a fixed passphrase from memory and records the
// prompt it was last asked with (for prompt threading) plus the success verdict
// it was told (for the PassphraseVerified contract).
type mockPassphraseProvider struct {
	passphrase []byte
	called     bool
	lastPrompt string

	verifiedCalled  bool
	verifiedSuccess bool
}

func (m *mockPassphraseProvider) ReadPassphrase(prompt string) ([]byte, error) {
	m.called = true
	m.lastPrompt = prompt
	return m.passphrase, nil
}

func (m *mockPassphraseProvider) PassphraseVerified(_ []byte, success bool) {
	m.verifiedCalled = true
	m.verifiedSuccess = success
}

func TestAskpassProviderReadsPassphrase(t *testing.T) {
	t.Parallel()
	helper := writeAskpassHelper(t, "printf '%s\\n' secret")

	passphrase, err := (&AskpassProvider{Program: helper}).ReadPassphrase("Prompt: ")
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), passphrase)
}

func TestAskpassProviderTrimsProgram(t *testing.T) {
	t.Parallel()
	helper := writeAskpassHelper(t, "printf flag")

	passphrase, err := (&AskpassProvider{Program: " " + helper + " "}).ReadPassphrase("Prompt: ")
	require.NoError(t, err)
	require.Equal(t, []byte("flag"), passphrase)
}

func TestAskpassProviderUnavailable(t *testing.T) {
	t.Parallel()
	_, err := (&AskpassProvider{}).ReadPassphrase("Prompt: ")
	require.ErrorIs(t, err, errAskpassUnavailable)
}

func TestAskpassProviderFallsBackWhenUnconfigured(t *testing.T) {
	t.Parallel()
	fallback := &mockPassphraseProvider{passphrase: []byte("fallback")}

	passphrase, err := (&AskpassProvider{Fallback: fallback}).ReadPassphrase("Prompt: ")
	require.NoError(t, err)
	require.Equal(t, []byte("fallback"), passphrase)
	require.True(t, fallback.called)
	require.Equal(t, "Prompt: ", fallback.lastPrompt)
}

func TestAskpassProviderDoesNotFallBackWhenHelperFails(t *testing.T) {
	t.Parallel()
	helper := writeAskpassHelper(t, "exit 1")
	fallback := &mockPassphraseProvider{passphrase: []byte("fallback")}

	_, err := (&AskpassProvider{Program: helper, Fallback: fallback}).ReadPassphrase("Prompt: ")
	require.Error(t, err)
	require.Contains(t, err.Error(), "askpass failed")
	require.False(t, fallback.called)
}

func writeAskpassHelper(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "askpass")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700))
	return path
}

// testScryptWorkFactor is a deliberately low scrypt log2(N) for test fixtures
// only (age's default is 18, ~1s). N=2^10 keeps encrypt/decrypt in the low ms.
const testScryptWorkFactor = 10

func encryptIdentityForTest(t *testing.T, plaintext string, passphrase []byte, armored bool) string {
	t.Helper()

	recipient, err := age.NewScryptRecipient(string(passphrase))
	require.NoError(t, err)
	// Tests only: age's default scrypt work factor (logN=18) is tuned to take
	// ~1s, and the header records it so decryption pays the same cost. Drop it
	// so the fixture encrypts and decrypts near-instantly; real identities keep
	// the secure default.
	recipient.SetWorkFactor(testScryptWorkFactor)

	var buf bytes.Buffer
	w := io.Writer(&buf)
	var armorWriter io.WriteCloser
	if armored {
		armorWriter = armor.NewWriter(&buf)
		w = armorWriter
	}

	ageWriter, err := age.Encrypt(w, recipient)
	require.NoError(t, err)
	_, err = ageWriter.Write([]byte(plaintext))
	require.NoError(t, err)
	require.NoError(t, ageWriter.Close())
	if armorWriter != nil {
		require.NoError(t, armorWriter.Close())
	}

	return buf.String()
}

func TestParseIdentityAgeNative(t *testing.T) {
	t.Parallel()
	ageID, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	id, err := ParseIdentity(ageID.String(), nil, nil, "")
	require.NoError(t, err)
	require.Equal(t, ageID.Recipient().String(), id.Public().String())
}

func TestParseIdentityAgePQ(t *testing.T) {
	t.Parallel()
	pqID, err := age.GenerateHybridIdentity()
	require.NoError(t, err)

	id, err := ParseIdentity(pqID.String(), nil, nil, "")
	require.NoError(t, err)
	require.Equal(t, pqID.Recipient().String(), id.Public().String())
}

func TestParseIdentitySSHEd25519Unencrypted(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(pemBlock)
	id, err := ParseIdentity(string(pemBytes), nil, nil, "")
	require.NoError(t, err)
	require.NotNil(t, id.Public())
}

func TestParseIdentitySSHEncryptedWithPassphrase(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	passphrase := []byte("test-passphrase-123")
	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", passphrase)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(pemBlock)

	// Should fail without a passphrase provider.
	_, err = ParseIdentity(string(pemBytes), nil, nil, "")
	require.Error(t, err, "should fail without passphrase")

	// Should succeed with the mock provider.
	mock := &mockPassphraseProvider{passphrase: passphrase}
	id, err := ParseIdentity(string(pemBytes), mock, nil, "")
	require.NoError(t, err)
	require.True(t, mock.called, "passphrase provider should have been called")
	require.NotNil(t, id.Public())
	require.True(t, mock.verifiedCalled, "PassphraseVerified must be called")
	require.True(t, mock.verifiedSuccess, "a correct passphrase must report success")
}

// The prompt argument to ParseIdentity must reach the PassphraseProvider so
// users with multiple --identity flags can see whose passphrase is asked for.
func TestParseIdentityForwardsPromptToProvider(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	passphrase := []byte("hunter2")
	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", passphrase)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(pemBlock)

	mock := &mockPassphraseProvider{passphrase: passphrase}
	_, err = ParseIdentity(string(pemBytes), mock, nil, "Passphrase for admin.age: ")
	require.NoError(t, err)
	require.Equal(t, "Passphrase for admin.age: ", mock.lastPrompt,
		"ParseIdentity must thread the prompt to PassphraseProvider")
}

func TestParseIdentitySSHWrongPassphrase(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("correct"))
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(pemBlock)
	mock := &mockPassphraseProvider{passphrase: []byte("wrong")}
	_, err = ParseIdentity(string(pemBytes), mock, nil, "")
	require.Error(t, err, "should fail with wrong passphrase")
	require.True(t, mock.verifiedCalled, "PassphraseVerified must be called even on failure")
	require.False(t, mock.verifiedSuccess, "a wrong passphrase must report failure")
}

func TestKeyFingerprintDistinctPerKey(t *testing.T) {
	t.Parallel()
	a := KeyFingerprint([]byte("key-a"))
	b := KeyFingerprint([]byte("key-b"))

	require.NotEqual(t, a, b, "different keys must get different fingerprints")
	require.Equal(t, a, KeyFingerprint([]byte("key-a")), "same key must be stable across calls")
	require.True(t, strings.HasPrefix(a, "sesam.identity."), "fingerprint should be namespaced")
}

// keyringGlobalMu serializes the tests that use the process-global keyring mock
// (keyring.MockInit resets a shared provider). They still run t.Parallel() so
// they overlap the other parallel tests instead of gating the sequential phase.
var keyringGlobalMu sync.Mutex

// A wrong passphrase must never be cached; only one that actually unlocks the
// key gets written to the keyring.
func TestKeyringPassphraseCachesOnlyOnSuccess(t *testing.T) {
	t.Parallel()
	keyringGlobalMu.Lock()
	defer keyringGlobalMu.Unlock()
	keyring.MockInit()

	pemBytes := encryptedSSHKey(t, "correct-horse")
	fp := KeyFingerprint(pemBytes)

	// Wrong passphrase from the fallback prompt -> must NOT be cached.
	wrong := &KeyringPassphraseProvider{
		KeyFingerprint: fp,
		Fallback:       &mockPassphraseProvider{passphrase: []byte("wrong")},
	}
	_, err := ParseIdentity(string(pemBytes), wrong, nil, "")
	require.Error(t, err)

	_, gerr := keyring.Get(keyringService, fp)
	require.Error(t, gerr, "a wrong passphrase must not be left in the keyring")

	// Correct passphrase -> cached now that it is verified.
	ok := &KeyringPassphraseProvider{
		KeyFingerprint: fp,
		Fallback:       &mockPassphraseProvider{passphrase: []byte("correct-horse")},
	}
	_, err = ParseIdentity(string(pemBytes), ok, nil, "")
	require.NoError(t, err)

	got, gerr := keyring.Get(keyringService, fp)
	require.NoError(t, gerr)
	require.Equal(t, "correct-horse", got, "a verified passphrase must be cached")
}

// A stale keyring entry whose passphrase no longer unlocks the key must be
// evicted, so a keyring-only load can recover instead of failing forever.
func TestKeyringPassphraseEvictsStaleEntry(t *testing.T) {
	t.Parallel()
	keyringGlobalMu.Lock()
	defer keyringGlobalMu.Unlock()
	keyring.MockInit()

	pemBytes := encryptedSSHKey(t, "correct-horse")
	fp := KeyFingerprint(pemBytes)

	require.NoError(t, keyring.Set(keyringService, fp, "stale-wrong"))

	// Keyring-only (no fallback): the stored passphrase is tried and fails.
	prov := &KeyringPassphraseProvider{KeyFingerprint: fp}
	_, err := ParseIdentity(string(pemBytes), prov, nil, "")
	require.Error(t, err)

	_, gerr := keyring.Get(keyringService, fp)
	require.Error(t, gerr, "stale keyring entry must be evicted after a failed unlock")
}

func TestParseIdentityPluginRequiresPublicKeyHeader(t *testing.T) {
	t.Parallel()
	identity := plugin.EncodeIdentity("yubikey", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})

	// Without # public key: header sesam can't match the identity to a user.
	_, err := ParseIdentity(identity, nil, NewInteractivePluginUI(), "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "public key")
}

func TestParseIdentityPluginWithPublicKeyHeader(t *testing.T) {
	t.Parallel()
	identity := plugin.EncodeIdentity("yubikey", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	recipient := plugin.EncodeRecipient("yubikey", []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})

	file := "# created: 2026-05-16\n# public key: " + recipient + "\n" + identity + "\n"

	id, err := ParseIdentity(file, nil, NewInteractivePluginUI(), "")
	require.NoError(t, err)
	require.Equal(t, recipient, id.Public().String())
}

func TestParseIdentityAgeKeyWithComments(t *testing.T) {
	t.Parallel()
	// age-keygen output: header comments followed by the secret line.
	ageID, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	file := "# created: 2026-05-16\n# public key: " + ageID.Recipient().String() + "\n" + ageID.String() + "\n"
	id, err := ParseIdentity(file, nil, nil, "")
	require.NoError(t, err)
	require.Equal(t, ageID.Recipient().String(), id.Public().String())
}

func TestParseIdentityEncryptedAgeNativeWithPassphrase(t *testing.T) {
	t.Parallel()
	ageID, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	passphrase := []byte("test-passphrase-123")
	key := encryptIdentityForTest(t, ageID.String()+"\n", passphrase, false)
	mock := &mockPassphraseProvider{passphrase: passphrase}

	id, err := ParseIdentity(key, mock, nil, "Passphrase for admin.age: ")
	require.NoError(t, err)
	require.True(t, mock.called, "passphrase provider should have been called")
	require.Equal(t, "Passphrase for admin.age: ", mock.lastPrompt)
	require.Equal(t, ageID.Recipient().String(), id.Public().String())
	require.True(t, mock.verifiedCalled, "PassphraseVerified must be called")
	require.True(t, mock.verifiedSuccess, "a correct passphrase must report success")
}

func TestParseIdentityEncryptedAgeArmored(t *testing.T) {
	t.Parallel()
	ageID, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	passphrase := []byte("test-passphrase-123")
	key := encryptIdentityForTest(t, ageID.String()+"\n", passphrase, true)
	mock := &mockPassphraseProvider{passphrase: passphrase}

	id, err := ParseIdentity(key, mock, nil, "")
	require.NoError(t, err)
	require.Equal(t, ageID.Recipient().String(), id.Public().String())
	require.True(t, mock.verifiedCalled, "PassphraseVerified must be called")
	require.True(t, mock.verifiedSuccess, "a correct passphrase must report success")
}

func TestParseIdentityEncryptedAgeRequiresPassphraseProvider(t *testing.T) {
	t.Parallel()
	ageID, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	key := encryptIdentityForTest(t, ageID.String()+"\n", []byte("correct"), false)
	_, err = ParseIdentity(key, nil, nil, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no passphrase supplied")
}

func TestParseIdentityEncryptedAgeWrongPassphrase(t *testing.T) {
	t.Parallel()
	ageID, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	key := encryptIdentityForTest(t, ageID.String()+"\n", []byte("correct"), false)
	mock := &mockPassphraseProvider{passphrase: []byte("wrong")}

	_, err = ParseIdentity(key, mock, nil, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decrypt age identity")
	require.True(t, mock.verifiedCalled, "PassphraseVerified must be called even on failure")
	require.False(t, mock.verifiedSuccess, "a wrong passphrase must report failure")
}

func TestScanAgeIdentity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		input    string
		wantLine string
		wantPub  string
	}{
		{
			name:     "bare age key",
			input:    "AGE-SECRET-KEY-1ABC",
			wantLine: "AGE-SECRET-KEY-1ABC",
			wantPub:  "",
		},
		{
			name:     "age-keygen output",
			input:    "# created: 2026-05-16\n# public key: age1xyz\nAGE-SECRET-KEY-1ABC\n",
			wantLine: "AGE-SECRET-KEY-1ABC",
			wantPub:  "age1xyz",
		},
		{
			name:     "plugin output",
			input:    "# public key: age1yubikey1xyz\nAGE-PLUGIN-YUBIKEY-1ABC",
			wantLine: "AGE-PLUGIN-YUBIKEY-1ABC",
			wantPub:  "age1yubikey1xyz",
		},
		{
			name:     "recipient header alternative",
			input:    "# recipient: age1yubikey1xyz\nAGE-PLUGIN-YUBIKEY-1ABC",
			wantLine: "AGE-PLUGIN-YUBIKEY-1ABC",
			wantPub:  "age1yubikey1xyz",
		},
		{
			name:     "capital Recipient header (age-plugin-yubikey)",
			input:    "#    Recipient: age1yubikey1xyz\nAGE-PLUGIN-YUBIKEY-1ABC",
			wantLine: "AGE-PLUGIN-YUBIKEY-1ABC",
			wantPub:  "age1yubikey1xyz",
		},
		{
			name:     "indented metadata header is ignored",
			input:    "#       Serial: 32876122, Slot: 1\n#    Recipient: age1yubikey1xyz\nAGE-PLUGIN-YUBIKEY-1ABC",
			wantLine: "AGE-PLUGIN-YUBIKEY-1ABC",
			wantPub:  "age1yubikey1xyz",
		},
		{
			name:     "blank lines tolerated",
			input:    "\n\n# public key: age1xyz\n\nAGE-SECRET-KEY-1ABC\n",
			wantLine: "AGE-SECRET-KEY-1ABC",
			wantPub:  "age1xyz",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotLine, gotPub := scanAgeIdentity(tc.input)
			require.Equal(t, tc.wantLine, gotLine)
			require.Equal(t, tc.wantPub, gotPub)
		})
	}
}

func TestParseIdentityInvalidInputs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		key  string
	}{
		{"empty string", ""},
		{"random garbage", "not-a-key-at-all"},
		{"truncated age key", "AGE-SECRET-KEY-1TRUNCATED"},
		{"truncated pq key", "AGE-SECRET-KEY-PQ-1TRUNCATED"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseIdentity(tc.key, nil, nil, "")
			require.Error(t, err)
		})
	}
}

func TestSshKeyToIdentityTypes(t *testing.T) {
	t.Parallel()
	t.Run("ed25519 value", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		id, err := sshKeyToIdentity(priv)
		require.NoError(t, err)
		require.NotNil(t, id.Public())
	})

	t.Run("ed25519 pointer", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		id, err := sshKeyToIdentity(&priv)
		require.NoError(t, err)
		require.NotNil(t, id.Public())
	})

	t.Run("rsa", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		id, err := sshKeyToIdentity(rsaKey)
		require.NoError(t, err)
		require.NotNil(t, id.Public())
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := sshKeyToIdentity("not a key")
		require.Error(t, err)
	})

	t.Run("nil", func(t *testing.T) {
		_, err := sshKeyToIdentity(nil)
		require.Error(t, err)
	})
}

func TestIdentityToUser(t *testing.T) {
	t.Parallel()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	t.Run("single match", func(t *testing.T) {
		userToPub := map[string]Recipients{
			"alice": {alice.Recipient},
			"bob":   {bob.Recipient},
		}
		matched, err := IdentityToUser(alice.Identity, userToPub)
		require.NoError(t, err)
		require.Equal(t, "alice", matched)
	})

	t.Run("no match", func(t *testing.T) {
		userToPub := map[string]Recipients{
			"bob": {bob.Recipient},
		}
		_, err := IdentityToUser(alice.Identity, userToPub)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no matching")
	})

	t.Run("multiple matches", func(t *testing.T) {
		userToPub := map[string]Recipients{
			"alice": {alice.Recipient},
			"clone": {alice.Recipient},
		}
		_, err := IdentityToUser(alice.Identity, userToPub)
		require.Error(t, err)
		require.Contains(t, err.Error(), "too many")
	})

	t.Run("empty map", func(t *testing.T) {
		_, err := IdentityToUser(alice.Identity, map[string]Recipients{})
		require.Error(t, err)
	})
}

func TestStringPubKeyEqual(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want bool
	}{
		{"age1abc", "age1abc", true},
		{"age1abc", "age1xyz", false},
		{"", "", true},
		{"age1abc", " age1abc ", true}, // newStringPubKey trims whitespace, so these become equal
	}

	for _, tc := range cases {
		a := newStringPubKey(tc.a)
		b := newStringPubKey(tc.b)
		require.Equal(t, tc.want, a.Equal(b), "Equal(%q, %q)", tc.a, tc.b)
	}

	// Different comparablePublicKey type should not be equal.
	a := newStringPubKey("age1abc")
	require.False(t, a.Equal(nil))
}

func TestIdentityPublic(t *testing.T) {
	t.Parallel()
	user := newTestUser(t, "alice")
	pub := user.Identity.Public()
	require.NotNil(t, pub)
	require.NotEmpty(t, pub.String())
}
