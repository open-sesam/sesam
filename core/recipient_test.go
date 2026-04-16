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

func TestResolveRecipientPassthrough(t *testing.T) {
	user := newTestUser(t, "alice")
	got, err := ResolveRecipient(context.Background(), "/tmp", user.Recipient.String(), CacheModeNone)
	require.NoError(t, err)
	require.Equal(t, user.Recipient.String(), got)
}

func TestResolveRecipientForgeIds(t *testing.T) {
	// Mock HTTP server that returns a key based on the request path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ssh-ed25519 AAAA %s", r.URL.Path)
	}))
	defer srv.Close()

	cases := []struct {
		name   string
		prefix string
		forge  string
	}{
		{"github", "github:", "github.com"},
		{"gitlab", "gitlab:", "gitlab.com"},
		{"codeberg", "codeberg:", "codeberg.org"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repoDir := testRepo(t)

			// Pre-populate cache with mock response to avoid real network calls.
			url := fmt.Sprintf("https://%s/%s.keys", tc.forge, "testuser")
			cp := cachePath(repoDir, url)
			os.MkdirAll(filepath.Dir(cp), 0700)
			os.WriteFile(cp, []byte("cached-key-"+tc.name), 0600)

			got, err := ResolveRecipient(context.Background(), repoDir, tc.prefix+"testuser", CacheModeRead)
			require.NoError(t, err)
			require.Equal(t, "cached-key-"+tc.name, got)
		})
	}
}

func TestResolveRecipientHTTPS(t *testing.T) {
	repoDir := testRepo(t)
	url := "https://example.com/keys"
	cp := cachePath(repoDir, url)
	os.MkdirAll(filepath.Dir(cp), 0700)
	os.WriteFile(cp, []byte("https-cached"), 0600)

	got, err := ResolveRecipient(context.Background(), repoDir, url, CacheModeRead)
	require.NoError(t, err)
	require.Equal(t, "https-cached", got)
}

func TestResolveCachedLinkCacheReadWrite(t *testing.T) {
	// Use httptest with plain HTTP won't work because resolveCachedLink rejects non-https.
	// Test cache read path.
	repoDir := testRepo(t)
	url := "https://example.com/test.keys"
	cp := cachePath(repoDir, url)
	os.MkdirAll(filepath.Dir(cp), 0700)
	os.WriteFile(cp, []byte("cached-value"), 0600)

	got, err := resolveCachedLink(context.Background(), repoDir, url, CacheModeRead)
	require.NoError(t, err)
	require.Equal(t, "cached-value", got)
}

func TestResolveCachedLinkNonHTTPS(t *testing.T) {
	_, err := resolveCachedLink(context.Background(), "/tmp", "http://example.com", CacheModeNone)
	require.Error(t, err, "should reject non-https URLs")
	require.Contains(t, err.Error(), "unsupported protocol")
}

func TestResolveCachedLinkCacheMiss(t *testing.T) {
	// No cache, no network — should try to download and fail (no real server).
	repoDir := testRepo(t)
	_, err := resolveCachedLink(context.Background(), repoDir, "https://192.0.2.1/nonexistent", CacheModeNone)
	require.Error(t, err, "should fail when cache misses and download fails")
}

func TestResolveRecipientFile(t *testing.T) {
	dir := t.TempDir()

	// ResolveRecipient does NOT strip "file://" — it calls os.ReadFile with the literal
	// "file://..." string. To avoid leaking a "file:" directory into the working directory,
	// create the literal path structure inside the temp dir and run the test from there.
	literalDir := filepath.Join(dir, "file:")
	require.NoError(t, os.MkdirAll(literalDir, 0700))
	literalFile := filepath.Join(literalDir, "key.pub")
	require.NoError(t, os.WriteFile(literalFile, []byte("age1testkey"), 0600))

	// The argument to ResolveRecipient: "file://key.pub" which os.ReadFile sees as "file://key.pub"
	// which is a relative path "file:/key.pub". We need to chdir to make this work.
	// Alternatively, just test the passthrough case since file:// is a broken TODO anyway.

	// Actually, just write the key at a path and use the full literal path.
	// Since os.ReadFile("file:///abs/path") interprets "file:" as first dir component,
	// we place it inside the temp dir and chdir there.
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { os.Chdir(origDir) })

	keyArg := "file://key.pub"
	got, err := ResolveRecipient(context.Background(), dir, keyArg, CacheModeNone)
	require.NoError(t, err)
	require.Equal(t, "age1testkey", got)
}

func TestResolveRecipientFileMissing(t *testing.T) {
	_, err := ResolveRecipient(context.Background(), "/tmp", "file:///nonexistent/key.pub", CacheModeNone)
	require.Error(t, err, "should fail for missing file")
}
