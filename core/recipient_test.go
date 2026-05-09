package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestParseRecipientAge(t *testing.T) {
	user := newTestUser(t, "alice")
	r, err := ParseRecipient(user.Recipient.String())
	require.NoError(t, err)
	require.Equal(t, user.Recipient.String(), r.String())
}

func TestParseRecipientSSH(t *testing.T) {
	// Generate an ed25519 SSH keypair and parse the public key as a recipient.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	authorizedKey := string(ssh.MarshalAuthorizedKey(sshPub))

	r, err := ParseRecipient(authorizedKey)
	require.NoError(t, err)
	require.NotNil(t, r)
	require.NotEmpty(t, r.String())
}

func TestParseRecipientInvalidInputs(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"garbage", "not-a-key"},
		{"truncated age", "age1truncated"},
		{"bad ssh prefix", "ssh-invalid AAAA"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRecipient(tc.key)
			require.Error(t, err)
		})
	}
}

func TestParseRecipientsFromSlice(t *testing.T) {
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	recps, err := ParseRecipients([]string{alice.Recipient.String(), bob.Recipient.String()})
	require.NoError(t, err)
	require.Len(t, recps, 2)
	require.Equal(t, alice.Recipient.String(), recps[0].String())
	require.Equal(t, bob.Recipient.String(), recps[1].String())
}

func TestParseRecipientsEmpty(t *testing.T) {
	// Empty slice should return empty recipients with no error (old "no recipient found" check was removed).
	recps, err := ParseRecipients([]string{})
	require.NoError(t, err)
	require.Empty(t, recps)
}

func TestParseRecipientsInvalidKey(t *testing.T) {
	_, err := ParseRecipients([]string{"not-a-key"})
	require.Error(t, err)
}

func TestRecipientsUserPubKeys(t *testing.T) {
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	rs := Recipients{alice.Recipient, bob.Recipient}

	want := []UserPubKey{
		{Key: alice.Recipient.String(), Source: KeySourceManual},
		{Key: bob.Recipient.String(), Source: KeySourceManual},
	}
	require.Equal(t, want, rs.UserPubKeys())
}

func TestRecipientsUserPubKeysEmpty(t *testing.T) {
	require.Empty(t, Recipients{}.UserPubKeys())
}

func TestForgeIdToUser(t *testing.T) {
	cases := []struct{ in, want string }{
		{"github:alice", "alice"},
		{"gitlab:bob", "bob"},
		{"codeberg:carol", "carol"},
		{"plain", ""},
	}

	for _, tc := range cases {
		require.Equal(t, tc.want, forgeIdToUser(tc.in), "forgeIdToUser(%q)", tc.in)
	}
}

func TestSplitByLine(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"empty", "", []string{}},
		{"single", "key1", []string{"key1"}},
		{"two keys", "key1\nkey2", []string{"key1", "key2"}},
		{"trailing newline", "key1\n", []string{"key1"}},
		{"blank lines filtered", "key1\n\nkey2\n", []string{"key1", "key2"}},
		{"spaces trimmed", "  key1  \n  key2  ", []string{"key1", "key2"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitByLine(tc.input)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestResolveRecipientPassthrough(t *testing.T) {
	user := newTestUser(t, "alice")
	got, source, err := ResolveRecipient(context.Background(), user.Recipient.String())
	require.NoError(t, err)
	require.Equal(t, []string{user.Recipient.String()}, got)
	require.Equal(t, KeySourceManual, source)
}

func TestResolveRecipientGitlabIsPassthrough(t *testing.T) {
	// GitLab uses JSON for keys (not the plain authorized_keys format) so it is
	// temporarily disabled - gitlab: args pass through unchanged.
	arg := "gitlab:testuser"
	got, source, err := ResolveRecipient(context.Background(), arg)
	require.NoError(t, err)
	require.Equal(t, []string{arg}, got)
	require.Equal(t, KeySourceManual, source)
}

func TestResolveRecipientFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pub")
	require.NoError(t, os.WriteFile(keyFile, []byte("age1testkey"), 0o600))

	keyArg := "file://" + keyFile
	got, source, err := ResolveRecipient(t.Context(), keyArg)
	require.NoError(t, err)
	require.Equal(t, []string{"age1testkey"}, got)
	require.Equal(t, KeySource(keyArg), source)
}

func TestResolveRecipientFileMissing(t *testing.T) {
	_, _, err := ResolveRecipient(context.Background(), "file:///nonexistent/key.pub")
	require.Error(t, err, "should fail for missing file")
}

func TestParseAndResolveRecipients(t *testing.T) {
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	recps, err := ParseAndResolveRecipients(
		context.Background(),
		[]string{alice.Recipient.String(), bob.Recipient.String()},
	)
	require.NoError(t, err)
	require.Len(t, recps, 2)
	require.Equal(t, KeySourceManual, recps[0].Source)
	require.Equal(t, KeySourceManual, recps[1].Source)
}

func TestParseAndResolveRecipientsInvalidKey(t *testing.T) {
	_, err := ParseAndResolveRecipients(context.Background(), []string{"not-a-key"})
	require.Error(t, err)
}

func TestParseAndResolveRecipientsEmpty(t *testing.T) {
	recps, err := ParseAndResolveRecipients(context.Background(), []string{})
	require.NoError(t, err)
	require.Empty(t, recps)
}

func TestResolveLinkSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "age1keydata")
	}))
	defer srv.Close()

	got, err := resolveLink(context.Background(), srv.URL+"/keys", srv.Client())
	require.NoError(t, err)
	require.Equal(t, []string{"age1keydata"}, got)
}

func TestResolveLinkMultipleKeys(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "key-one\nkey-two\nkey-three")
	}))
	defer srv.Close()

	got, err := resolveLink(context.Background(), srv.URL+"/keys", srv.Client())
	require.NoError(t, err)
	require.Equal(t, []string{"key-one", "key-two", "key-three"}, got)
}

func TestResolveLinkNonHTTPS(t *testing.T) {
	_, err := resolveLink(context.Background(), "http://example.com")
	require.Error(t, err, "should reject non-https URLs")
	require.Contains(t, err.Error(), "unsupported protocol")
}

func TestResolveLinkHTTP4xx(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := resolveLink(context.Background(), srv.URL+"/keys", srv.Client())
	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

func TestIdentitiesRecipientStrings(t *testing.T) {
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	ids := Identities{alice.Identity, bob.Identity}
	strs := ids.RecipientStrings()

	require.Len(t, strs, 2)
	require.Contains(t, strs, alice.Recipient.String())
	require.Contains(t, strs, bob.Recipient.String())
}

func TestIdentitiesRecipientStringsMatchesRecipient(t *testing.T) {
	// RecipientStrings() must return the same keys that the corresponding Recipients would.
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	identity := &Identity{
		Identity: id,
		pub:      newStringPubKey(id.Recipient().String()),
	}
	ids := Identities{identity}

	strs := ids.RecipientStrings()
	require.Equal(t, []string{id.Recipient().String()}, strs)
}
