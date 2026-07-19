package core

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeduplicateStrings(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"with duplicates", []string{"b", "a", "b", "c", "a"}, []string{"a", "b", "c"}},
		{"already unique", []string{"c", "b", "a"}, []string{"a", "b", "c"}},
		{"empty", []string{}, nil},
		{"single", []string{"x"}, []string{"x"}},
		{"all same", []string{"a", "a", "a"}, []string{"a"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deduplicate(tc.in)
			if tc.want == nil {
				require.Empty(t, got)
			} else {
				require.Equal(t, tc.want, got)
			}
		})
	}
}

func TestDeduplicateInts(t *testing.T) {
	got := deduplicate([]int{3, 1, 2, 1, 3})
	require.Equal(t, []int{1, 2, 3}, got)
}

func TestValidUserName(t *testing.T) {
	valid := []string{
		"alice",
		"bob-admin",
		"user_42",
		"a",
		"a-b-c",
		"alice.bob",
		"user@host",
		"c.pohl@hermanbionic.com",
		"Alice",
	}

	for _, name := range valid {
		require.NoError(t, ValidUserName(name), "should accept %q", name)
	}
}

func TestValidUserNameRejects(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"dot-dot", ".."},
		{"path traversal", "../admin"},
		{"dot-dot in email", "a..b@host"},
		{"slash", "alice/bob"},
		{"backslash", `alice\bob`},
		{"space", "alice bob"},
		{"colon", "user:name"},
		{"unicode", "alicё"},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, ValidUserName(tc.input), "should reject %q", tc.input)
		})
	}
}

type failCloser struct{}

func (fc failCloser) Close() error {
	return errors.New("close failed")
}

func TestIsForbiddenPathSesamSubdir(t *testing.T) {
	// A relative path that points inside .sesam/ must be rejected.
	err := IsForbiddenPath(filepath.Join(".sesam", "signkeys", "admin.age"))
	require.Error(t, err)
	require.Contains(t, err.Error(), ".sesam")
}

func TestValidSecretPathFormatNormalPath(t *testing.T) {
	require.NoError(t, validSecretPathFormat("secrets/db_password"))
}

// sesam.yml is sesam's own config and must never be sealed as a secret,
// regardless of which directory it lives in.
func TestIsForbiddenPathRejectsSesamYml(t *testing.T) {
	cases := []string{
		"sesam.yml",
		filepath.Join("config", "sesam.yml"),
		filepath.Join("a", "b", "sesam.yml"),
	}

	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			err := IsForbiddenPath(path)
			require.Error(t, err, "should reject %q", path)
			require.Contains(t, err.Error(), "sesam.yml")
		})
	}
}

// Anything living inside a .sesam directory must be rejected no matter where
// the component appears in the path.
func TestIsForbiddenPathRejectsDotSesam(t *testing.T) {
	cases := []struct {
		name        string
		revealed    string
		wantMessage string
	}{
		{"leading", filepath.Join(".sesam", "secret"), ".sesam"},
		{"signkey", filepath.Join(".sesam", "signkeys", "admin.age"), ".sesam"},
		{"nested component", filepath.Join("a", ".sesam", "b"), ".sesam"},
		{"bare", ".sesam", ".sesam"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := IsForbiddenPath(tc.revealed)
			require.Error(t, err, "should reject %q", tc.revealed)
			require.Contains(t, err.Error(), tc.wantMessage)
		})
	}
}

// A regular secret path that merely mentions "sesam" must still be allowed -
// only the exact .sesam component and sesam.yml file are forbidden.
func TestIsForbiddenPathAllowsLookalikes(t *testing.T) {
	cases := []string{
		filepath.Join("sesam", "secret"),       // dir named "sesam", not ".sesam"
		filepath.Join("secrets", "sesam.yaml"), // .yaml, not .yml
		"sesam.yml.bak",                        // not exactly sesam.yml
		filepath.Join("my.sesam.dir", "x"),     // component contains, isn't, .sesam
	}

	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			require.NoError(t, IsForbiddenPath(path), "should accept %q", path)
		})
	}
}

func TestCloseLoggedNoError(t *testing.T) {
	// Should not panic.
	require.NotPanics(t, func() {
		closeLogged(failCloser{})
	})
}

func TestReadFileLimitedTooLarge(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "toobig")
	require.NoError(t, err)
	_, err = f.Write([]byte("hello world"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = ReadFileLimited(f.Name(), 5)
	require.Error(t, err, "should fail when file exceeds limit")
	require.Contains(t, err.Error(), "would be limited")
}

func TestReadFileLimitedExactSize(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "exact")
	require.NoError(t, err)
	_, err = f.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	data, err := ReadFileLimited(f.Name(), 5)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), data)
}

func TestReadFileLimitedMissing(t *testing.T) {
	_, err := ReadFileLimited("/nonexistent/path", 100)
	require.Error(t, err)
}

// On a normal filesystem (tmpfs/ext4/...) CopyFile must hardlink:
// dst should share the same inode as src. We rely on Stat().Sys() being
// a *syscall.Stat_t on unix. The test is skipped on platforms where
// that doesn't hold.
func TestCopyFileHardlinksWhenPossible(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src"), []byte("payload"), 0o600))

	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })

	require.NoError(t, CopyFile(root, "src", "dst", true))

	srcInfo, err := os.Stat(filepath.Join(dir, "src"))
	require.NoError(t, err)
	dstInfo, err := os.Stat(filepath.Join(dir, "dst"))
	require.NoError(t, err)
	require.True(t, os.SameFile(srcInfo, dstInfo),
		"CopyFile should hardlink when src and dst sit on the same fs")

	// Sanity: contents match.
	got, err := os.ReadFile(filepath.Join(dir, "dst"))
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), got)
}

// When the hardlink fails (e.g. dst already exists), CopyFile must fall
// back to a byte-for-byte copy and not surface an error.
func TestCopyFileFallsBackOnLinkFailure(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src"), []byte("payload"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dst"), []byte("stale"), 0o600))

	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })

	require.NoError(t, CopyFile(root, "src", "dst", true))

	got, err := os.ReadFile(filepath.Join(dir, "dst"))
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), got)

	srcInfo, err := os.Stat(filepath.Join(dir, "src"))
	require.NoError(t, err)
	dstInfo, err := os.Stat(filepath.Join(dir, "dst"))
	require.NoError(t, err)
	require.False(t, os.SameFile(srcInfo, dstInfo),
		"fallback path should produce a fresh inode, not link to src")
}
