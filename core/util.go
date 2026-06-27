package core

import (
	"cmp"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// PruneEmptyDirs removes directories beneath dir (a root-relative path) whose
// subtree contains no regular files, deepest first. dir itself is never
// removed, nor is any directory whose root-relative path is in `except“ (those
// are skipped without descending). If allow is non-nil it is called for each
// removal candidate - return true to allow and return an error to stop
// entirely.
func PruneEmptyDirs(root *os.Root, dir string, except map[string]bool, allow func(rel string) (bool, error)) ([]string, error) {
	dir = filepath.Clean(dir)
	if _, err := root.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	hasFile := map[string]bool{} // dirs with a file somewhere in their subtree
	var candidates []string

	walkErr := fs.WalkDir(root.FS(), filepath.ToSlash(dir), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := filepath.FromSlash(p)
		if d.IsDir() {
			if rel == dir {
				return nil
			}
			if except[rel] {
				return fs.SkipDir
			}
			candidates = append(candidates, rel)
			return nil
		}
		// Mark every ancestor up to (and including) dir as non-empty.
		for a := filepath.Dir(rel); ; a = filepath.Dir(a) {
			hasFile[a] = true
			if a == dir || a == "." {
				break
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	var empties []string
	for _, c := range candidates {
		if !hasFile[c] {
			empties = append(empties, c)
		}
	}
	// Deepest first, so a parent is only removed after its emptied children.
	slices.SortFunc(empties, func(a, b string) int { return len(b) - len(a) })

	removed := make([]string, 0, len(empties))
	for _, e := range empties {
		if allow != nil {
			ok, err := allow(e)
			if err != nil {
				return removed, err
			}
			if !ok {
				continue
			}
		}
		if err := root.Remove(e); err != nil {
			return removed, fmt.Errorf("remove empty dir %s: %w", e, err)
		}
		removed = append(removed, e)
	}
	return removed, nil
}

// defaultSesamBase is the sesam-internal directory name. A stage uses a
// sibling fork directory instead; see sesamBase.
const defaultSesamBase = ".sesam"

// sesamBase resolves the sesam-internal base directory. The empty string means
// the live ".sesam" tree; a stage passes its fork dir (".sesam-tmp") so the
// same path helpers write into the fork. All paths under this base are swapped
// atomically on commit, so the temp dir (SesamTmpDir) stays in the live tree:
// renameio renames cross-tree within the same os.Root.
func sesamBase(base string) string {
	if base == "" {
		return defaultSesamBase
	}
	return base
}

// SesamTmpDir is the repo-relative scratch directory for the live tree. It is
// passed to renameio as the temp dir so atomic writes stage inside .sesam/
// rather than at the repo root (and never in the worktree). Callers must ensure
// it exists; ensureSesamDirs and BuildSecretManager do.
func SesamTmpDir() string {
	return sesamTmpDir("")
}

// sesamTmpDir is SesamTmpDir under a given base. A stage passes its fork dir so
// renameio temps for fork operations land inside the fork and are reaped with
// it on rollback/crash — there is then nothing stray to garbage-collect in the
// live tree.
func sesamTmpDir(base string) string {
	return filepath.Join(sesamBase(base), "tmp")
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

// paths that are required for sesam to work,
// so they shouldn't be encrypted...
var forbiddenBasenames = map[string]bool{
	".gitignore":               true,
	".gitattributes":           true,
	"sesam.yml":                true,
	defaultSesamBase + ".lock": true,
}

func IsForbiddenPath(revealedPath string) error {
	if b := filepath.Base(revealedPath); forbiddenBasenames[b] {
		return fmt.Errorf("you can't seal %s", b)
	}

	for _, elem := range strings.Split(revealedPath, string(filepath.Separator)) {
		if elem == ".sesam" {
			return fmt.Errorf("encrypting files in .sesam/ is not allowed")
		}

		if elem == ".sesam-tmp" {
			return fmt.Errorf("encrypting files in .sesam-tmp/ is not allowed")
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

// CopyFile materializes `dst` with the same contents as `src`. When tryLink is
// set it attempts a hardlink first (zero-copy when src and dst sit on the same
// filesystem and the FS supports it - Linux/macOS/BSD via link(2), Windows on
// NTFS via CreateHardLinkW) and falls back to a byte-for-byte copy on any error
// (EXDEV across mounts, EPERM on FAT/some FUSE, EEXIST, ...). Pass tryLink=false
// to force a copy (e.g. for a file the caller intends to mutate independently of
// src, like the staged audit log).
//
// Hardlinks share the source inode, so dst inherits its mode/owner/mtime. The
// byte copy creates a fresh inode at mode 0o600. The caller (the repo stage
// fork) operates exclusively under .sesam/ (0o700 dirs, 0o600 files), so no
// permission widening can result either way. The byte-copy path fsyncs dst; a
// hardlink does not (its inode data is already durable, and the new directory
// entry's durability is the caller's concern, e.g. via a directory fsync).
func CopyFile(root *os.Root, src, dst string, tryLink bool) error {
	// A hardlink shares src's already-durable inode, so it needs no fsync (the
	// new directory entry's durability is the caller's concern). A byte copy
	// creates a fresh inode whose data we fsync before returning.
	if tryLink {
		if err := root.Link(src, dst); err == nil {
			return nil
		}
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
	if err := dstFd.Sync(); err != nil {
		_ = dstFd.Close()
		return fmt.Errorf("sync %s: %w", dst, err)
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
