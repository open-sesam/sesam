package core

import (
	"cmp"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// validUserName checks that a user name is safe for use in file paths and log entries.
// Only lowercase alphanumeric characters, hyphens and underscores are allowed.
// The name must not be empty and must not exceed 64 characters.
func validUserName(name string) error {
	if name == "" {
		return fmt.Errorf("user name must not be empty")
	}

	if len(name) > 64 {
		return fmt.Errorf("user name too long: %d characters (max 64)", len(name))
	}

	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return fmt.Errorf("user name contains invalid character: %q", r)
		}
	}

	return nil
}

// ValidUserName checks user name format for external callers.
func ValidUserName(name string) error {
	return validUserName(name)
}

func validSecretPath(repoDir string, revealedPath string) error {
	if len(revealedPath) == 0 {
		return fmt.Errorf("empty file path not allowed: %s", revealedPath)
	}

	if revealedPath[0] == filepath.Separator {
		return fmt.Errorf("absolute paths not allowed here: %s", revealedPath)
	}

	if strings.Contains(revealedPath, "..") {
		return fmt.Errorf("path may not include '..': %s", revealedPath)
	}

	revealedPath = filepath.Clean(revealedPath)
	info, err := os.Stat(revealedPath)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", revealedPath, err)
	}

	if m := info.Mode(); !m.IsRegular() {
		return fmt.Errorf("%s is not a regular file: %v", revealedPath, m)
	}

	return nil
}

// Deduplicate returns a sorted copy of s with duplicates removed.
func deduplicate[T cmp.Ordered](s []T) []T {
	c := slices.Clone(s)
	slices.Sort(c)
	return slices.Compact(c)
}

func closeLogged(fd io.Closer) {
	if err := fd.Close(); err != nil {
		slog.Warn(
			"failed to close descriptor",
			slog.Any("err", err),
			slog.Any("fd", fd),
		)
	}
}

func ReadFileLimited(path string, size int64) ([]byte, error) {
	//nolint:gosec
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	//nolint:errcheck
	defer fd.Close()
	return io.ReadAll(io.LimitReader(fd, size))
}
