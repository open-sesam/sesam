package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppendMissingLines(t *testing.T) {
	cases := []struct {
		name     string
		existing string // "" means file does not exist
		content  string
		want     string
	}{
		{
			name:     "create from scratch",
			existing: "",
			content:  "a\nb\n",
			want:     "a\nb\n",
		},
		{
			name:     "append new line only",
			existing: "a\n",
			content:  "a\nb\n",
			want:     "a\nb\n",
		},
		{
			name:     "no change leaves file untouched",
			existing: "a\nb\n",
			content:  "a\nb\n",
			want:     "a\nb\n",
		},
		{
			name:     "blank lines in content are ignored",
			existing: "",
			content:  "a\n\n\nb\n",
			want:     "a\nb\n",
		},
		{
			name:     "existing without trailing newline gets one",
			existing: "a",
			content:  "a\nb\n",
			want:     "a\nb\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "out")

			if tc.existing != "" {
				require.NoError(t, os.WriteFile(path, []byte(tc.existing), 0o600))
			}

			require.NoError(t, appendMissingLines(path, tc.content, 0o600))

			got, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(got))
		})
	}
}

func TestRemoveManagedLines(t *testing.T) {
	const missing = "\x00" // sentinel: file should not exist

	cases := []struct {
		name     string
		existing string // missing means no file on disk
		content  string
		want     string // missing means the file must be gone
	}{
		{
			name:     "removes only sesam lines, keeps user lines",
			existing: "user rule\na\nb\n",
			content:  "a\nb\n",
			want:     "user rule\n",
		},
		{
			name:     "file that held only sesam lines is deleted",
			existing: "a\nb\n",
			content:  "a\nb\n",
			want:     missing,
		},
		{
			name:     "matching ignores surrounding whitespace",
			existing: "  a  \nkeep\n",
			content:  "a\n",
			want:     "keep\n",
		},
		{
			name:     "nothing managed present leaves content",
			existing: "x\ny\n",
			content:  "a\nb\n",
			want:     "x\ny\n",
		},
		{
			name:     "missing file is a no-op",
			existing: missing,
			content:  "a\nb\n",
			want:     missing,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "out")

			if tc.existing != missing {
				require.NoError(t, os.WriteFile(path, []byte(tc.existing), 0o600))
			}

			require.NoError(t, removeManagedLines(path, tc.content, 0o600))

			got, err := os.ReadFile(path)
			if tc.want == missing {
				require.ErrorIs(t, err, os.ErrNotExist)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, string(got))
		})
	}
}

// clearGitAttributes must undo ensureDefaultGitAttributes: sesam's lines go
// away, a user's own lines survive, and a file sesam solely created is removed.
// The suffix must round-trip (install and clear use the same one) and reach the
// driver references, so several sesam repos can carry distinct drivers.
func TestClearGitAttributes(t *testing.T) {
	t.Run("round-trips to a removed file", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, ensureDefaultGitAttributes(dir, "-sub"))
		require.FileExists(t, filepath.Join(dir, ".gitattributes"))

		require.NoError(t, clearGitAttributes(dir, "-sub"))
		require.NoFileExists(t, filepath.Join(dir, ".gitattributes"))
	})

	t.Run("suffix reaches the driver references", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, ensureDefaultGitAttributes(dir, "-sub"))

		got, err := os.ReadFile(filepath.Join(dir, ".gitattributes"))
		require.NoError(t, err)
		require.Contains(t, string(got), "merge=sesam-merge-secret-sub")
		require.Contains(t, string(got), "diff=sesam-diff-sub")
	})

	t.Run("preserves user lines", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".gitattributes")
		require.NoError(t, os.WriteFile(path, []byte("*.txt text\n"), 0o600))

		require.NoError(t, ensureDefaultGitAttributes(dir, ""))
		require.NoError(t, clearGitAttributes(dir, ""))

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, "*.txt text\n", string(got))
	})

	t.Run("missing file is a no-op", func(t *testing.T) {
		require.NoError(t, clearGitAttributes(t.TempDir(), ""))
	})
}

// wrapHookCmd must guard on sesam's presence and keep the sesam call last, so
// git's appended "$@" reaches it and a missing binary skips the hook (exit 0)
// rather than aborting the commit with "command not found".
func TestWrapHookCmd(t *testing.T) {
	got := wrapHookCmd("sesam --sesam-dir=sub hook pre-commit")
	require.Equal(
		t,
		"command -v sesam >/dev/null 2>&1 || exit 0; exec sesam --sesam-dir=sub hook pre-commit",
		got,
	)
}

func TestQuoteYAMLString(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "''"},
		{"plain", "'plain'"},
		{"o'malley", "'o''malley'"},
		{"newline\nstays", "'newline\nstays'"},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.want, quoteYAMLString(tc.in))
		})
	}
}

// shellQuote feeds the `filter.sesam-filter.process` config value,
// which git runs via `/bin/sh -c`. Anything that isn't a portable
// path character must end up POSIX-quoted, otherwise nested layouts
// with spaces or quotes in their path break smudge silently.
func TestShellQuote(t *testing.T) {
	cases := []struct {
		name string
		in   string
		out  string
	}{
		{"plain", "sub", "sub"},
		{"slash", "path/to/sesam", "path/to/sesam"},
		{"safe meta", "a-b_c.d+e:f@g~h", "a-b_c.d+e:f@g~h"},
		{"space", "my dir", `'my dir'`},
		{"dollar", "$HOME/sesam", `'$HOME/sesam'`},
		{"backtick", "a`b", "'a`b'"},
		{"single quote", "o'malley", `'o'\''malley'`},
		{"double quote", `say "hi"`, `'say "hi"'`},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.out, shellQuote(tc.in))
		})
	}
}
