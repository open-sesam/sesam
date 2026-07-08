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

// SesamTmpDir is the repo-relative scratch directory. It is passed to renameio
// as the temp dir so atomic writes stage inside .sesam/ rather than at the repo
// root (and never in the worktree). Callers must ensure it exists; ensureSesamDirs
// and BuildSecretManager do.
func SesamTmpDir() string {
	return filepath.Join(".sesam", "tmp")
}

// ValidUserName checks that a user name is safe for use in file paths and log entries.
// Only alphanumeric characters (mixed case), hyphens, underscores, '@' and '.'
// are allowed. The name must not be empty and must not exceed 64 characters.
func ValidUserName(name string) error {
	if name == "" {
		return fmt.Errorf("user name must not be empty")
	}

	if len(name) > 64 {
		return fmt.Errorf("user name too long: %d characters (max 64)", len(name))
	}

	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '@' && r != '.' {
			return fmt.Errorf("user name contains invalid character: %q", r)
		}
	}

	if strings.Contains(name, "..") {
		return fmt.Errorf("name may not include '..': %s", name)
	}

	return nil
}

func IsForbiddenPath(revealedPath string) error {
	if revealedPath == ".sesam" || strings.HasPrefix(revealedPath, ".sesam"+string(filepath.Separator)) {
		return fmt.Errorf("secret path may not live in .sesam: %s", revealedPath)
	}

	if filepath.Base(revealedPath) == "sesam.yml" {
		return fmt.Errorf("you can't seal sesam.yml")
	}

	if filepath.Base(revealedPath) == ".gitattributes" {
		return fmt.Errorf("you shouldn't seal .gitattributes")
	}

	for _, elem := range strings.Split(revealedPath, string(filepath.Separator)) {
		if elem == ".sesam" {
			return fmt.Errorf("encrypting files in .sesam/ is not allowed")
		}

		if elem == ".git" {
			return fmt.Errorf("encrypting files in .git/ is not allowed")
		}
	}

	return nil
}

func validSecretPathFormat(revealedPath string) error {
	if len(revealedPath) == 0 {
		return fmt.Errorf("empty file path not allowed: %s", revealedPath)
	}

	if revealedPath[0] == filepath.Separator {
		return fmt.Errorf("absolute paths not allowed in revealed path: %s", revealedPath)
	}

	if strings.Contains(revealedPath, "..") {
		return fmt.Errorf("path may not include '..': %s", revealedPath)
	}

	return nil
}

// validSecretPath checks the path format and that it points at a regular file
// inside the repository. The stat goes through root so it cannot escape it.
func validSecretPath(root *os.Root, revealedPath string) error {
	if err := validSecretPathFormat(revealedPath); err != nil {
		return err
	}

	info, err := root.Stat(revealedPath)
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

// PathExists reports whether `p` is reachable via os.Stat. It does not
// distinguish between "missing" and "permission denied" - it simply
// answers "can I see something there?".
func PathExists(p string) bool {
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
func copyFile(root *os.Root, src, dst string) error {
	if err := root.Link(src, dst); err == nil {
		return nil
	}

	srcFd, err := root.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer closeLogged(srcFd)

	dstFd, err := root.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}

	if _, err := io.Copy(dstFd, srcFd); err != nil {
		_ = dstFd.Close()
		_ = root.Remove(dst)
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	return dstFd.Close()
}

// readFileLimitedRoot is ReadFileLimited confined to root.
func readFileLimitedRoot(root *os.Root, path string, size int64) ([]byte, error) {
	fd, err := root.Open(path)
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
