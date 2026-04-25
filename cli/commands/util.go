package commands

import (
	"os"
	"path/filepath"
	"strings"
)

// expandHomeDir expands "~" and "~/..." in CLI path input.
func expandHomeDir(path string) (string, error) {
	switch {
	case path == "~":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		return homeDir, nil
	case strings.HasPrefix(path, "~/"):
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		return filepath.Join(homeDir, strings.TrimPrefix(path, "~/")), nil
	default:
		return path, nil
	}
}
