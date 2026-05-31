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
