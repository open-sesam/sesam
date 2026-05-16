package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// mockPassphraseProvider serves a fixed passphrase from memory.
type mockPassphraseProvider struct {
	passphrase []byte
	called     bool
}

func (m *mockPassphraseProvider) ReadPassphrase() ([]byte, error) {
	m.called = true
	return m.passphrase, nil
}

func TestParseIdentityAgeNative(t *testing.T) {
	ageID, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	id, err := ParseIdentity(ageID.String(), nil, nil)
	require.NoError(t, err)
	require.Equal(t, ageID.Recipient().String(), id.Public().String())
}

func TestParseIdentityAgePQ(t *testing.T) {
	pqID, err := age.GenerateHybridIdentity()
	require.NoError(t, err)

	id, err := ParseIdentity(pqID.String(), nil, nil)
	require.NoError(t, err)
	require.Equal(t, pqID.Recipient().String(), id.Public().String())
}

func TestParseIdentitySSHEd25519Unencrypted(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(pemBlock)
	id, err := ParseIdentity(string(pemBytes), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, id.Public())
}

func TestParseIdentitySSHEncryptedWithPassphrase(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	passphrase := []byte("test-passphrase-123")
	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", passphrase)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(pemBlock)

	// Should fail without a passphrase provider.
	_, err = ParseIdentity(string(pemBytes), nil, nil)
	require.Error(t, err, "should fail without passphrase")

	// Should succeed with the mock provider.
	mock := &mockPassphraseProvider{passphrase: passphrase}
	id, err := ParseIdentity(string(pemBytes), mock, nil)
	require.NoError(t, err)
	require.True(t, mock.called, "passphrase provider should have been called")
	require.NotNil(t, id.Public())
}

func TestParseIdentitySSHWrongPassphrase(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("correct"))
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(pemBlock)
	mock := &mockPassphraseProvider{passphrase: []byte("wrong")}
	_, err = ParseIdentity(string(pemBytes), mock, nil)
	require.Error(t, err, "should fail with wrong passphrase")
}

func TestParseIdentityPluginRequiresPublicKeyHeader(t *testing.T) {
	identity := plugin.EncodeIdentity("yubikey", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})

	// Without # public key: header sesam can't match the identity to a user.
	_, err := ParseIdentity(identity, nil, NewInteractivePluginUI())
	require.Error(t, err)
	require.Contains(t, err.Error(), "public key")
}

func TestParseIdentityPluginWithPublicKeyHeader(t *testing.T) {
	identity := plugin.EncodeIdentity("yubikey", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	recipient := plugin.EncodeRecipient("yubikey", []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})

	file := "# created: 2026-05-16\n# public key: " + recipient + "\n" + identity + "\n"

	id, err := ParseIdentity(file, nil, NewInteractivePluginUI())
	require.NoError(t, err)
	require.Equal(t, recipient, id.Public().String())
}

func TestParseIdentityAgeKeyWithComments(t *testing.T) {
	// age-keygen output: header comments followed by the secret line.
	ageID, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	file := "# created: 2026-05-16\n# public key: " + ageID.Recipient().String() + "\n" + ageID.String() + "\n"
	id, err := ParseIdentity(file, nil, nil)
	require.NoError(t, err)
	require.Equal(t, ageID.Recipient().String(), id.Public().String())
}

func TestScanAgeIdentity(t *testing.T) {
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
			_, err := ParseIdentity(tc.key, nil, nil)
			require.Error(t, err)
		})
	}
}

func TestSshKeyToIdentityTypes(t *testing.T) {
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
	user := newTestUser(t, "alice")
	pub := user.Identity.Public()
	require.NotNil(t, pub)
	require.NotEmpty(t, pub.String())
}
