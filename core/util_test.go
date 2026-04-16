package core

import (
	"errors"
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
	}

	for _, name := range valid {
		require.NoError(t, validUserName(name), "should accept %q", name)
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
		{"slash", "alice/bob"},
		{"backslash", `alice\bob`},
		{"space", "alice bob"},
		{"uppercase", "Alice"},
		{"dot", "alice.bob"},
		{"at sign", "user@host"},
		{"colon", "user:name"},
		{"unicode", "alicё"},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, validUserName(tc.input), "should reject %q", tc.input)
		})
	}
}

type failCloser struct{}

func (fc failCloser) Close() error {
	return errors.New("close failed")
}

func TestCloseLoggedNoError(t *testing.T) {
	// Should not panic.
	require.NotPanics(t, func() {
		closeLogged(failCloser{})
	})
}
