package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", ""},
		{"exact tag", "v0.1.2", "0.1.2"},
		{"exact tag without v", "0.1.2", "0.1.2"},
		{"commits past tag", "v0.1.2-5-gae27c29", "0.1.2-dev+5"},
		{"commits past tag dirty", "v0.1.2-5-gae27c29-dirty", "0.1.2-dev+5"},
		{"bare hash (no tag)", "ae27c29", ""},
		{"bare hash dirty", "ae27c29-dirty", ""},
		{"prerelease tag exact", "v1.0.0-rc1", "1.0.0-rc1"},
		{"prerelease tag ahead", "v1.0.0-rc1-2-gabc1234", "1.0.0-rc1-dev+2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, normalizeVersion(tt.raw))
		})
	}
}

func TestCopyrightYears(t *testing.T) {
	tests := []struct {
		name string
		year string
		want string
	}{
		{"unknown", "unknown", copyrightStart},
		{"empty", "", copyrightStart},
		{"same as start", copyrightStart, copyrightStart},
		{"before start", "2025", copyrightStart},
		{"after start", "2028", copyrightStart + "-2028"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, buildInfo{Year: tt.year}.copyrightYears())
		})
	}
}
