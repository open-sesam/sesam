package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// Group names are held to the user-name rules - an access list mixes the two
// and matches them against each other - so the two validators have to agree on
// every name, and the list form has to name the entry it rejects.
func TestValidGroupName(t *testing.T) {
	names := []string{
		"dev", "ops-team", "team_42", "a", "Admin", "svc@host", "a.b",
		"", "..", "../admin", "a..b", "dev/ops", `dev\ops`, "dev ops", "dev:ops",
		"dévs", strings.Repeat("g", 65),
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			groupErr := ValidGroupName(name)
			require.Equal(t, ValidUserName(name) == nil, groupErr == nil,
				"group and user rules must agree on %q", name)

			listErr := ValidGroupNames([]string{"dev", name, "ops"})
			if groupErr == nil {
				require.NoError(t, listErr)
				return
			}

			require.ErrorContains(t, groupErr, "group name")
			require.ErrorContains(t, listErr, "invalid group")
		})
	}

	// The list form names the offender, not just the rule it broke.
	require.ErrorContains(t, ValidGroupNames([]string{"dev", "bad group"}), "bad group")
}

type failCloser struct{}

func (fc failCloser) Close() error {
	return errors.New("close failed")
}

func TestIsForbiddenPathSesamSubdir(t *testing.T) {
	// A relative path that points inside .sesam/ must be rejected.
	err := IsForbiddenPath(".sesam/signkeys/admin.age")
	require.Error(t, err)
	require.Contains(t, err.Error(), ".sesam")
}

func TestValidSecretPathFormatNormalPath(t *testing.T) {
	require.NoError(t, validSecretPathFormat("secrets/db_password"))
}

func TestValidSecretPathFormat(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{name: "plain", path: "secrets/db_password"},
		// ".." inside a filename is legitimate and must not be mistaken for
		// path traversal (the bug this guards against).
		{name: "dots in filename", path: "geo/countries/hong_kong_s.a.r..geojson"},
		{name: "trailing double dot", path: "dir/weird..txt"},
		{name: "leading double dot in name", path: "dir/..weird"},
		{name: "empty", path: "", wantErr: "empty file path"},
		{name: "absolute", path: "/etc/passwd", wantErr: "absolute paths"},
		{name: "traversal segment", path: "../secret", wantErr: "'..' segment"},
		{name: "traversal in middle", path: "a/../../etc/passwd", wantErr: "'..' segment"},
		// Same two, spelled the way the OS would - on Windows these are the
		// ones a split on "/" alone would miss.
		{name: "traversal os separator", path: filepath.Join("..", "secret"), wantErr: "'..' segment"},
		{name: "absolute os separator", path: string(filepath.Separator) + "etc", wantErr: "absolute paths"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validSecretPathFormat(tc.path)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// sesam.yml is sesam's own config and must never be sealed as a secret,
// regardless of which directory it lives in.
func TestIsForbiddenPathRejectsSesamYml(t *testing.T) {
	cases := []string{
		"sesam.yml",
		"config/sesam.yml",
		"a/b/sesam.yml",
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
	// Revealed paths are stored slash-separated, so that form has to be
	// rejected on every platform - splitting on the OS separator would let it
	// pass on Windows. The filepath.Join rows keep the native form covered.
	cases := []struct {
		name        string
		revealed    string
		wantMessage string
	}{
		{"leading", ".sesam/secret", ".sesam"},
		{"signkey", ".sesam/signkeys/admin.age", ".sesam"},
		{"nested component", "a/.sesam/b", ".sesam"},
		{"bare", ".sesam", ".sesam"},
		{"git dir", "a/.git/config", ".git"},
		{"tmp dir", "a/.sesam-tmp/x", ".sesam-tmp"},
		{"os separator", filepath.Join("a", ".sesam", "b"), ".sesam"},
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

func TestPruneEmptyDirs(t *testing.T) {
	tcs := []struct {
		Name             string
		CreateDirs       []string
		CreateFiles      []string
		Except           map[string]bool
		ExpectedToDelete []string
	}{
		{
			Name:             "basic",
			CreateDirs:       []string{"empty"},
			ExpectedToDelete: []string{"empty"},
		},
		{
			Name:             "except",
			CreateDirs:       []string{".git"},
			Except:           map[string]bool{".git": true},
			ExpectedToDelete: []string{},
		},
		{
			Name:       "nested",
			CreateDirs: []string{"sub1/sub2/sub3"},
			ExpectedToDelete: []string{
				"sub1/sub2/sub3",
				"sub1/sub2",
				"sub1",
			},
		},
		{
			Name:        "nested_with_file",
			CreateDirs:  []string{"sub1/sub2/sub3"},
			CreateFiles: []string{"sub1/file"},
			ExpectedToDelete: []string{
				"sub1/sub2/sub3",
				"sub1/sub2",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			dir := t.TempDir()
			for _, d := range tc.CreateDirs {
				require.NoError(t, os.MkdirAll(filepath.Join(dir, d), 0o700))
			}
			for _, p := range tc.CreateFiles {
				require.NoError(t, os.WriteFile(filepath.Join(dir, p), nil, 0o600))
			}

			root, err := os.OpenRoot(dir)
			require.NoError(t, err)
			t.Cleanup(func() { _ = root.Close() })

			deleted, err := PruneEmptyDirs(root, ".", tc.Except, nil)
			require.NoError(t, err)
			require.Equal(t, tc.ExpectedToDelete, deleted)
		})
	}
}
