package commands

import (
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunSecretFile(t *testing.T) {
	for _, content := range []string{"", "a\x00b\n", "certificate\nkey\n"} {
		t.Run(content, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("TMPDIR", dir)
			file, err := runSecretFile([]byte(content))
			require.NoError(t, err)
			t.Cleanup(func() { _ = file.Close() })
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Empty(t, entries)
			info, err := file.Stat()
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o400), info.Mode().Perm())
			require.Zero(t, info.Sys().(*syscall.Stat_t).Nlink)
			got, err := io.ReadAll(file)
			require.NoError(t, err)
			require.Equal(t, content, string(got))
			_, err = file.Write([]byte("overwrite"))
			require.ErrorIs(t, err, syscall.EBADF)
			require.NoError(t, file.Close())
			entries, err = os.ReadDir(dir)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}
