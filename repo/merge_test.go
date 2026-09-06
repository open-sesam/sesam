package repo

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/core"
)

// Taking anything from the incoming branch before it was verified is what the
// whole check exists to prevent, so a provider that cannot produce a state must
// stop the merge rather than fall back to an unchecked decrypt.
func TestDecryptTheirSecretRefusesWithoutState(t *testing.T) {
	_, _, err := decryptTheirSecret(
		core.Identities{},
		"s",
		filepath.Join(t.TempDir(), "nonexistent"),
		func() (*core.VerifiedState, error) {
			return nil, errors.New("the branch being merged in was never verified")
		},
	)

	require.ErrorContains(t, err, "never verified")
}

func TestClearTmp(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, core.SesamTmpDir(), "theirs", ".sesam"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, core.SesamTmpDir(), "theirs-vstate.json"), []byte("{}"), 0o600))

	root, err := os.OpenRoot(dir)
	require.NoError(t, err)

	defer func() { _ = root.Close() }()

	require.NoError(t, ClearTmp(root))

	left, err := os.ReadDir(filepath.Join(dir, core.SesamTmpDir()))
	require.NoError(t, err)
	require.Empty(t, left)

	// Clearing twice is not an error, and neither is clearing what is not there.
	require.NoError(t, ClearTmp(root))
}
