package repo

import (
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/go-git/go-git/v5"
)

// recursiveRmEmptyDirs will recursively delete all empty directories in
// `rootDir`, except they are in the `except` map. The list of deleted
// directories is returned (path relative to rootDir) and possibly an error.
func recursiveRmEmptyDirs(rootDir string, except map[string]bool) ([]string, error) {
	dirMap := make(map[string]bool)

	if err := filepath.WalkDir(rootDir, func(path string, ent os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		var err error
		path, err = filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}

		if ent.IsDir() {
			if except[path] {
				return filepath.SkipDir
			}

			if path == "." {
				// can't delete self
				return nil
			}

			dirMap[path] = true
		} else {
			for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
				// delete all dirs that have this file in it - they are obviously not empty
				delete(dirMap, dir)
				if dir == "/" || dir == "." || dir == rootDir {
					break
				}
			}
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("first pass rmdir failed: %w", err)
	}

	emptyDirs := slices.Collect(maps.Keys(dirMap))
	slices.SortFunc(emptyDirs, func(a, b string) int {
		// sort by inverse length to delete lower rank dirs first
		return len(b) - len(a)
	})

	for idx, emptyDir := range emptyDirs {
		if err := os.Remove(filepath.Join(rootDir, emptyDir)); err != nil {
			return emptyDirs[:idx], fmt.Errorf("failed to delete empty dir %s: %w", emptyDir, err)
		}
	}

	if emptyDirs == nil {
		// just for tests...
		emptyDirs = []string{}
	}

	return emptyDirs, nil
}

// Cleanup removes every file under sesamRoot that is not in the git index.
// .sesam/ and .git/ are skipped entirely - sesam owns one, git owns the
// other. The intent is to wipe stale revealed plaintext (which is gitignored
// and therefore "untracked") before a smudge pass repopulates the worktree
// from sealed objects, so files removed in the new tree do not linger as
// readable plaintext.
//
// Tracked files are preserved even when modified; symlinks and other
// non-regular entries are left alone. The optional exclude list holds
// absolute paths that must not be deleted even if untracked - intended for
// identity files that happen to live inside the worktree.
func Cleanup(repo *git.Repository, sesamDir string, exclude ...string) error {
	var err error
	sesamDir, err = filepath.Abs(sesamDir)
	if err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(sesamDir, ".sesam")); err != nil {
		return fmt.Errorf("not a sesam directory %q: %w", sesamDir, err)
	}

	excluded := make(map[string]bool, len(exclude))
	for _, p := range exclude {
		abs, err := filepath.Abs(p)
		if err == nil {
			excluded[abs] = true
		}
	}

	idx, err := repo.Storer.Index()
	if err != nil {
		return fmt.Errorf("read git index: %w", err)
	}

	tracked := make(map[string]struct{}, len(idx.Entries))
	for _, e := range idx.Entries {
		tracked[filepath.FromSlash(e.Name)] = struct{}{}
	}

	if err := filepath.WalkDir(sesamDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == sesamDir {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == ".sesam" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		rel, err := filepath.Rel(
			sesamDir,
			path,
		)
		if err != nil {
			return fmt.Errorf("rel path: %w", err)
		}

		if _, ok := tracked[rel]; ok {
			return nil
		}

		if excluded[path] {
			return nil
		}

		if err := os.Remove(path); err != nil { //nolint:gosec
			return fmt.Errorf("remove %s: %w", path, err)
		}

		slog.Debug("clean: removed untracked file", slog.String("path", path))
		return nil
	}); err != nil {
		return err
	}

	// Deleting might have created some empty dirs.
	// Make sure we delete them too.
	_, err = recursiveRmEmptyDirs(sesamDir, map[string]bool{
		".sesam": true,
		".git":   true,
	})
	return err
}
