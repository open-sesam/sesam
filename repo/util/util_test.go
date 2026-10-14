package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSortedSetNeverNil pins the property SortedSet exists for and
// core.Deduplicate does not provide: an absent and an empty set must render
// the same, which matters once a caller serializes the result to JSON (a nil
// slice with omitempty vanishes from the output; an empty one does not).
func TestSortedSetNeverNil(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, []string{}},
		{"empty", []string{}, []string{}},
		{"duplicates removed and sorted", []string{"b", "a", "b"}, []string{"a", "b"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SortedSet(tc.in)
			require.NotNil(t, got)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestWithAdmin(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"adds admin when absent", []string{"dev"}, []string{"admin", "dev"}},
		{"admin already present is not duplicated", []string{"admin", "dev"}, []string{"admin", "dev"}},
		{"nil becomes just admin", nil, []string{"admin"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, WithAdmin(tc.in))
		})
	}
}
