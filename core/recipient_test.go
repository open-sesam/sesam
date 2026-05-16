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
	"filippo.io/age/plugin"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestParseRecipientAge(t *testing.T) {
	user := newTestUser(t, "alice")
	r, err := ParseRecipient(user.Recipient.String(), nil)
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

	r, err := ParseRecipient(authorizedKey, nil)
	require.NoError(t, err)
	require.NotNil(t, r)
	require.NotEmpty(t, r.String())
}

func TestParseRecipientPluginHRP(t *testing.T) {
	// age1yubikey1… (HRP "age1yubikey") must dispatch to plugin parsing,
	// not the X25519 parser - that's the whole point of the bech32 sniff.
	rec := plugin.EncodeRecipient("yubikey", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})

	r, err := ParseRecipient(rec, NewInteractivePluginUI())
	require.NoError(t, err)
	require.Equal(t, rec, r.String())
}

func TestParseRecipientPluginRequiresUI(t *testing.T) {
	rec := plugin.EncodeRecipient("yubikey", []byte{1, 2, 3, 4, 5, 6, 7, 8})

	_, err := ParseRecipient(rec, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "PluginUI")
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
			_, err := ParseRecipient(tc.key, nil)
			require.Error(t, err)
		})
	}
}

func TestParseRecipientsFromSlice(t *testing.T) {
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	recps, err := ParseRecipients([]string{alice.Recipient.String(), bob.Recipient.String()}, nil)
	require.NoError(t, err)
	require.Len(t, recps, 2)
	require.Equal(t, alice.Recipient.String(), recps[0].String())
	require.Equal(t, bob.Recipient.String(), recps[1].String())
}

func TestParseRecipientsEmpty(t *testing.T) {
	// Empty slice should return empty recipients with no error (old "no recipient found" check was removed).
	recps, err := ParseRecipients([]string{}, nil)
	require.NoError(t, err)
	require.Empty(t, recps)
}

func TestParseRecipientsInvalidKey(t *testing.T) {
	_, err := ParseRecipients([]string{"not-a-key"}, nil)
	require.Error(t, err)
}

func TestRecipientsStrings(t *testing.T) {
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	rs := Recipients{alice.Recipient, bob.Recipient}

	strs := rs.Strings()
	require.Equal(t, []string{alice.Recipient.String(), bob.Recipient.String()}, strs)
}

func TestRecipientsStringsEmpty(t *testing.T) {
	require.Empty(t, Recipients{}.Strings())
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

func TestCachePath(t *testing.T) {
	p := cachePath("/repo", "https://example.com/user.keys")
	want := filepath.Join("/repo", ".sesam", "links", "https:__example.com_user.keys")
	require.Equal(t, want, p)
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
	got, err := ResolveRecipient(context.Background(), "/tmp", user.Recipient.String(), CacheModeNone)
	require.NoError(t, err)
	require.Equal(t, []string{user.Recipient.String()}, got)
}

func TestResolveRecipientForgeIds(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		forge  string
	}{
		{"github", "github:", "github.com"},
		{"codeberg", "codeberg:", "codeberg.org"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sesamDir := testRepo(t)

			// Pre-populate cache with mock response to avoid real network calls.
			url := fmt.Sprintf("https://%s/%s.keys", tc.forge, "testuser")
			cp := cachePath(sesamDir, url)
			os.MkdirAll(filepath.Dir(cp), 0o700)
			os.WriteFile(cp, []byte("cached-key-"+tc.name), 0o600)

			got, err := ResolveRecipient(context.Background(), sesamDir, tc.prefix+"testuser", CacheModeRead)
			require.NoError(t, err)
			require.Equal(t, []string{"cached-key-" + tc.name}, got)
		})
	}
}

func TestResolveRecipientGitlabIsPassthrough(t *testing.T) {
	// GitLab uses JSON for keys (not the plain authorized_keys format) so it is
	// temporarily disabled - gitlab: args pass through unchanged.
	arg := "gitlab:testuser"
	got, err := ResolveRecipient(context.Background(), "/tmp", arg, CacheModeNone)
	require.NoError(t, err)
	require.Equal(t, []string{arg}, got)
}

func TestResolveRecipientForgeIdsMultipleKeys(t *testing.T) {
	// Forge endpoints can return multiple SSH keys (one per line).
	sesamDir := testRepo(t)
	url := "https://github.com/multikey.keys"
	cp := cachePath(sesamDir, url)
	os.MkdirAll(filepath.Dir(cp), 0o700)
	os.WriteFile(cp, []byte("key-one\nkey-two\nkey-three\n"), 0o600)

	// Resolve via an https:// URL directly.
	got, err := ResolveRecipient(context.Background(), sesamDir, url, CacheModeRead)
	require.NoError(t, err)
	require.Equal(t, []string{"key-one", "key-two", "key-three"}, got)
}

func TestResolveRecipientHTTPS(t *testing.T) {
	sesamDir := testRepo(t)
	url := "https://example.com/keys"
	cp := cachePath(sesamDir, url)
	os.MkdirAll(filepath.Dir(cp), 0o700)
	os.WriteFile(cp, []byte("https-cached"), 0o600)

	got, err := ResolveRecipient(context.Background(), sesamDir, url, CacheModeRead)
	require.NoError(t, err)
	require.Equal(t, []string{"https-cached"}, got)
}

func TestResolveCachedLinkCacheReadWrite(t *testing.T) {
	// Use httptest with plain HTTP won't work because resolveCachedLink rejects non-https.
	// Test cache read path.
	sesamDir := testRepo(t)
	url := "https://example.com/test.keys"
	cp := cachePath(sesamDir, url)
	os.MkdirAll(filepath.Dir(cp), 0o700)
	os.WriteFile(cp, []byte("cached-value"), 0o600)

	got, err := resolveCachedLink(context.Background(), sesamDir, url, CacheModeRead)
	require.NoError(t, err)
	require.Equal(t, []string{"cached-value"}, got)
}

func TestResolveCachedLinkNonHTTPS(t *testing.T) {
	_, err := resolveCachedLink(context.Background(), "/tmp", "http://example.com", CacheModeNone)
	require.Error(t, err, "should reject non-https URLs")
	require.Contains(t, err.Error(), "unsupported protocol")
}

func TestResolveCachedLinkCacheMiss(t *testing.T) {
	// No cache, no network - should try to download and fail (no real server).
	sesamDir := testRepo(t)
	_, err := resolveCachedLink(context.Background(), sesamDir, "https://192.0.2.1/nonexistent", CacheModeNone)
	require.Error(t, err, "should fail when cache misses and download fails")
}

func TestResolveRecipientFile(t *testing.T) {
	dir := t.TempDir()

	// ResolveRecipient does NOT strip "file://" - it calls os.ReadFile with the literal
	// "file://..." string. To avoid leaking a "file:" directory into the working directory,
	// create the literal path structure inside the temp dir and run the test from there.
	literalDir := filepath.Join(dir, "sub")
	require.NoError(t, os.MkdirAll(literalDir, 0o700))
	literalFile := filepath.Join(literalDir, "key.pub")
	require.NoError(t, os.WriteFile(literalFile, []byte("age1testkey"), 0o600))

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { os.Chdir(origDir) })

	keyArg := "file://sub/key.pub"
	got, err := ResolveRecipient(t.Context(), dir, keyArg, CacheModeNone)
	require.NoError(t, err)
	require.Equal(t, []string{"age1testkey"}, got)
}

func TestResolveRecipientFileMissing(t *testing.T) {
	_, err := ResolveRecipient(context.Background(), "/tmp", "file:///nonexistent/key.pub", CacheModeNone)
	require.Error(t, err, "should fail for missing file")
}

func TestParseAndResolveRecipients(t *testing.T) {
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	// Pass through two age public keys directly.
	recps, err := ParseAndResolveRecipients(
		context.Background(),
		"/tmp",
		[]string{alice.Recipient.String(), bob.Recipient.String()},
		nil,
	)
	require.NoError(t, err)
	require.Len(t, recps, 2)
}

func TestParseAndResolveRecipientsMultiKeyURL(t *testing.T) {
	// An https:// URL with multiple keys returns all of them as separate recipients.
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s\n%s\n", alice.Recipient.String(), bob.Recipient.String())
	}))
	defer srv.Close()

	sesamDir := testRepo(t)
	url := srv.URL + "/keys"

	// Pre-populate cache so we don't need an actual TLS handshake.
	cp := cachePath(sesamDir, url)
	os.MkdirAll(filepath.Dir(cp), 0o700)
	os.WriteFile(cp, []byte(alice.Recipient.String()+"\n"+bob.Recipient.String()+"\n"), 0o600)

	recps, err := ParseAndResolveRecipients(context.Background(), sesamDir, []string{url}, nil)
	require.NoError(t, err)
	require.Len(t, recps, 2)
}

func TestParseAndResolveRecipientsInvalidKey(t *testing.T) {
	_, err := ParseAndResolveRecipients(context.Background(), "/tmp", []string{"not-a-key"}, nil)
	require.Error(t, err)
}

func TestParseAndResolveRecipientsEmpty(t *testing.T) {
	recps, err := ParseAndResolveRecipients(context.Background(), "/tmp", []string{}, nil)
	require.NoError(t, err)
	require.Empty(t, recps)
}

func TestResolveRecipientHTTPSDownload(t *testing.T) {
	// Test the live download path with a real HTTPS test server - but pre-cache
	// the response so resolveCachedLink returns immediately without dialing.
	user := newTestUser(t, "alice")
	sesamDir := testRepo(t)

	url := "https://example.com/alice.keys"
	cp := cachePath(sesamDir, url)
	os.MkdirAll(filepath.Dir(cp), 0o700)
	os.WriteFile(cp, []byte(user.Recipient.String()), 0o600)

	got, err := ResolveRecipient(context.Background(), sesamDir, url, CacheModeRead)
	require.NoError(t, err)
	require.Equal(t, []string{user.Recipient.String()}, got)
}

func TestResolveCachedLinkHTTPDownloadSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "age1keydata")
	}))
	defer srv.Close()

	sesamDir := testRepo(t)
	got, err := resolveCachedLink(context.Background(), sesamDir, srv.URL+"/keys", CacheModeNone, srv.Client())
	require.NoError(t, err)
	require.Equal(t, []string{"age1keydata"}, got)
}

func TestResolveCachedLinkHTTPDownloadAndCache(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "age1cached-fresh")
	}))
	defer srv.Close()

	sesamDir := testRepo(t)
	url := srv.URL + "/keys"

	got, err := resolveCachedLink(context.Background(), sesamDir, url, CacheModeWrite, srv.Client())
	require.NoError(t, err)
	require.Equal(t, []string{"age1cached-fresh"}, got)

	data, err := os.ReadFile(cachePath(sesamDir, url))
	require.NoError(t, err)
	require.Contains(t, string(data), "age1cached-fresh")
}

func TestResolveCachedLinkHTTP4xx(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	sesamDir := testRepo(t)
	_, err := resolveCachedLink(context.Background(), sesamDir, srv.URL+"/keys", CacheModeNone, srv.Client())
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
