package commands

import (
	"encoding/json"
	"fmt"
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

func printJSON(value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal json output: %w", err)
	}

	fmt.Println(string(payload))
	return nil
}
