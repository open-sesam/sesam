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
