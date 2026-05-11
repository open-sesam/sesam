package repo

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
