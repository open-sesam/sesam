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

func validSecretPathFormat(sesamDir string, revealedPath string) error {
	if len(revealedPath) == 0 {
		return fmt.Errorf("empty file path not allowed: %s", revealedPath)
	}

	if revealedPath[0] == filepath.Separator {
		return fmt.Errorf("absolute paths not allowed in revealed path: %s", revealedPath)
	}

	if strings.Contains(revealedPath, "..") {
		return fmt.Errorf("path may not include '..': %s", revealedPath)
	}

	if strings.HasPrefix(revealedPath, filepath.Join(sesamDir, ".sesam")) {
		return fmt.Errorf("secret path may not live in .sesam: %s", revealedPath)
	}

	return nil
}

func validSecretPath(sesamDir string, revealedPath string) error {
	if err := validSecretPathFormat(sesamDir, revealedPath); err != nil {
		return err
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

// pathExists reports whether `p` is reachable via os.Stat. It does not
// distinguish between "missing" and "permission denied" - it simply
// answers "can I see something there?".
func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// copyFile materializes `dst` with the same contents as `src`. It tries
// a hardlink first (zero-copy when src and dst sit on the same
// filesystem and the FS supports it - Linux/macOS/BSD via link(2),
// Windows on NTFS via CreateHardLinkW) and falls back to a byte-for-byte
// copy on any error (EXDEV across mounts, EPERM on FAT/some FUSE,
// EEXIST, ...).
//
// Hardlinks share the source inode, so dst inherits its mode/owner/mtime.
// The byte copy creates a fresh inode at mode 0o600. Both call sites
// today operate exclusively under .sesam/ (0o700 dirs, 0o600 files) so
// no permission widening can result either way.
func copyFile(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}

	//nolint:gosec
	srcFd, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer closeLogged(srcFd)

	//nolint:gosec
	dstFd, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}

	if _, err := io.Copy(dstFd, srcFd); err != nil {
		_ = dstFd.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	return dstFd.Close()
}

// TODO: Add WriteAgeFile() and ReadAgeFile() utils

func ReadFileLimited(path string, size int64) ([]byte, error) {
	//nolint:gosec
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	info, err := fd.Stat()
	if err != nil {
		_ = fd.Close()
		return nil, err
	}

	if is := info.Size(); is > size {
		_ = fd.Close()
		return nil, fmt.Errorf("file would be limited: %s: %d > %d", path, is, size)
	}

	//nolint:errcheck
	defer fd.Close()
	return io.ReadAll(io.LimitReader(fd, size))
}
