package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/test-go/testify/require"
)

// TestRemoveSecrets_DoesNotMisattributeComments documents bug #1: the
// CommentMap is keyed by positional path ($.secrets[i]), and the encoder
// re-resolves that path against the mutated AST. When the first secret is
// removed, the surviving secret shifts into slot 0 and inherits the removed
// secret's head comment.
//
// This test currently FAILS: the comment that belonged to the removed secret
// reappears attached to the surviving one.
func TestRemoveSecrets_DoesNotMisattributeComments(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	body := `secrets:
  # comment-for-alpha
  - path: alpha.txt
    access:
      - group1
  - path: beta.txt
    access:
      - group1
`
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))
	// RemoveSecrets stats the path, so the plaintext files must exist.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beta.txt"), []byte("x"), 0o644))

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.RemoveSecrets(filepath.Join(dir, "alpha.txt"), false))
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)

	// alpha is gone, so its comment must be gone too — it must not have moved
	// onto beta.
	require.NotContains(t, string(out), "comment-for-alpha",
		"removed secret's comment was misattributed to the surviving secret:\n%s", out)

	fmt.Println(string(out))
}
