package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/test-go/testify/require"
)

// TestRemoveSecrets_DoesNotMisattributeComments guards against the comment
// misattribution that the positional CommentMap used to cause: removing the
// first secret shifted the surviving one into slot 0, where it inherited the
// removed secret's head comment.
//
// Comments now live on the AST nodes themselves (parser.ParseComments) and are
// cut out with their node, so the removed secret's comment must not survive on
// the one that remains.
func TestRemoveSecrets_DoesNotMisattributeComments(t *testing.T) {
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
	// RemoveSecrets stats the path, so the plaintext files must exist.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beta.txt"), []byte("x"), 0o644))

	cr, err := Load(main)
	require.NoError(t, err)
	_, err = cr.RemoveSecrets(filepath.Join(dir, "alpha.txt"))
	require.NoError(t, err)
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

// TestAddSecrets_PreservesExistingComments verifies that inserting a new secret
// node leaves the comments on the pre-existing entries untouched — the new node
// is appended, nothing above it shifts.
func TestAddSecrets_PreservesExistingComments(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	body := `secrets:
  # comment-for-alpha
  - path: alpha.txt
    access:
      - group1
`
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beta.txt"), []byte("x"), 0o644))

	cr, err := Load(main)
	require.NoError(t, err)
	_, err = cr.AddSecrets(filepath.Join(dir, "beta.txt"), false, []string{"group1"})
	require.NoError(t, err)
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)

	require.Contains(t, string(out), "comment-for-alpha", "existing comment was lost on add:\n%s", out)
	require.Contains(t, string(out), "beta.txt", "added secret missing:\n%s", out)
}

// TestAddSecrets_PreservesCommentsAndIndentation checks that altering the config
// leaves the existing entry byte-for-byte intact (comment + exact indentation)
// and appends the new entry with the same block-sequence indentation.
func TestAddSecrets_PreservesCommentsAndIndentation(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	body := `secrets:
  # keep me
  - path: alpha.txt
    access:
      - group1
`
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beta.txt"), []byte("x"), 0o644))

	cr, err := Load(main)
	require.NoError(t, err)
	_, err = cr.AddSecrets(filepath.Join(dir, "beta.txt"), false, []string{"group2"})
	require.NoError(t, err)
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)
	got := string(out)

	// The original entry — comment and its exact indentation — is untouched.
	require.Contains(t, got, "  # keep me\n  - path: alpha.txt\n    access:\n      - group1\n",
		"existing comment/indentation was altered:\n%s", got)
	// The appended entry matches the same indentation style.
	require.Contains(t, got, "  - path: beta.txt\n    access:\n      - group2\n",
		"added entry has unexpected indentation:\n%s", got)
}

// TestRemoveSecrets_RemovesCommentWithNode verifies that removing a node in the
// middle of the sequence takes its head comment with it, while the comments on
// the surrounding entries stay put.
func TestRemoveSecrets_RemovesCommentWithNode(t *testing.T) {
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

	cr, err := Load(main)
	require.NoError(t, err)
	_, err = cr.RemoveSecrets(filepath.Join(dir, "beta.txt"))
	require.NoError(t, err)
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
