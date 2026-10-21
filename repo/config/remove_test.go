package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildConfig writes a main sesam.yml, touches every given file and adds them
// one at a time via SecretAdd, then saves. It returns the temp dir and the main
// file path.
func buildConfig(t *testing.T, nested bool, files ...string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	main := writeMainFile(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	for _, f := range files {
		p := filepath.Join(dir, f)
		touch(t, p)
		require.NoError(t, cr.SecretAdd(f, nested, []string{"group1"}))
	}
	require.NoError(t, cr.Save())

	return dir, main
}

// TestSecretRemove_FileFromMain removes a single secret stored in the main
// file; the rest stay and the plaintext file remains (no purge).
func TestSecretRemove_FileFromMain(t *testing.T) {
	dir, main := buildConfig(t, false, "token.txt")

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretRemove("token.txt"))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt"}, resolvedPaths(t, main))
	require.True(t, exists(filepath.Join(dir, "token.txt")), "plaintext is left for the user to delete")
}

// TestSecretRemove_FileFromSubfile removes the only secret in a subdirectory
// file: the sub sesam.yml is deleted and its include dropped from main.
func TestSecretRemove_FileFromSubfile(t *testing.T) {
	dir, main := buildConfig(t, true, "sub/api.key")

	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretRemove(filepath.Join("sub", "api.key")))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt"}, resolvedPaths(t, main))
	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")), "empty sub file removed")
	require.True(t, exists(filepath.Join(dir, "sub", "api.key")), "plaintext is left for the user to delete")
}

// TestSecretRemove_SubfileKeepsSecret removes one of several secrets in a
// subdirectory file; the file (and its include) survive.
func TestSecretRemove_SubfileKeepsSecret(t *testing.T) {
	dir, main := buildConfig(t, true, "sub/b.txt", "sub/c.txt")

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretRemove(filepath.Join("sub", "b.txt")))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"c.txt", "existing.txt"}, resolvedPaths(t, main))
	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")), "non-empty sub file kept")
}

// TestSecretRemove_NotFound errors when nothing matches the path.
func TestSecretRemove_NotFound(t *testing.T) {
	_, main := buildConfig(t, false)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.Error(t, cr.SecretRemove("stray.txt"))
}

// TestSecretRemove_DoesNotMisattributeComments guards against the comment
// misattribution that the positional CommentMap used to cause: removing the
// first secret shifted the surviving one into slot 0, where it inherited the
// removed secret's head comment.
//
// Comments now live on the AST nodes themselves (parser.ParseComments) and are
// cut out with their node, so the removed secret's comment must not survive on
// the one that remains.
func TestSecretRemove_DoesNotMisattributeComments(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	body := `secrets:
  # comment-for-alpha
  - path: alpha.txt
    access:
      - group1
  # comment-for-beta
  - path: beta.txt
    access:
      - group1
`
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beta.txt"), []byte("x"), 0o644))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretRemove("alpha.txt"))
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)

	// alpha is gone, so its comment must be gone too — it must not have moved
	// onto beta.
	require.NotContains(t, string(out), "comment-for-alpha",
		"removed secret's comment was misattributed to the surviving secret:\n%s", out)
	// beta and its own comment must survive.
	require.Contains(t, string(out), "comment-for-beta", "surviving secret's comment was dropped:\n%s", out)
	require.Contains(t, string(out), "beta.txt")
}

// TestSecretRemove_RemovesCommentWithNode verifies that removing a node in the
// middle of the sequence takes its head comment with it, while the comments on
// the surrounding entries stay put.
func TestSecretRemove_RemovesCommentWithNode(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	body := `secrets:
  # comment-alpha
  - path: alpha.txt
    access:
      - group1
  # comment-beta
  - path: beta.txt
    access:
      - group1
  # comment-gamma
  - path: gamma.txt
    access:
      - group1
`
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))
	for _, f := range []string{"alpha.txt", "beta.txt", "gamma.txt"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644))
	}

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretRemove("beta.txt"))
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)
	got := string(out)

	require.NotContains(t, got, "comment-beta", "removed node's comment must be gone:\n%s", got)
	require.NotContains(t, got, "beta.txt")
	// Neighbours and their comments survive.
	require.Contains(t, got, "comment-alpha")
	require.Contains(t, got, "comment-gamma")
}
