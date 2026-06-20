package repo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/go-git/go-git/v5"
	"github.com/open-sesam/sesam/core"
)

// CleanAggressive removes every untracked file under sesamDir, including
// scratch state inside `.sesam/`. It is the package-level analogue of
// `git clean -fdx` and does not require a loaded repository.
func CleanAggressive(_ context.Context, sesamDir string, identityPaths []string, opts CleanOpts) error {
	gr, err := openGitRepo(sesamDir)
	if err != nil {
		return err
	}
	return cleanup(gr, sesamDir, opts.CheckFunc, identityPaths...)
}

// deleteRevealedSecrets removes the plaintext copy on disk for every
// VerifiedSecret in `secrets`, ignoring already-absent files.
func deleteRevealedSecrets(sesamDir string, secrets []core.VerifiedSecret, checkFn func(path string) (bool, error)) error {
	for _, secret := range secrets {
		revealedPath := filepath.Join(sesamDir, secret.RevealedPath)

		allow := true
		if checkFn != nil {
			var err error
			allow, err = checkFn(revealedPath)
			if err != nil {
				return err
			}
		}

		if allow {
			if err := os.Remove(revealedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("failed to delete %s: %w", secret.RevealedPath, err)
			}
		}
	}

	return nil
}

// recursiveRmEmptyDirs will recursively delete all empty directories in
// `rootDir`, except they are in the `except` map. If checkFn is non-nil it
// is consulted before each removal: a false result keeps the directory
// (used to keep --dry-run honest). The list of deleted directories is
// returned (path relative to rootDir) and possibly an error.
func recursiveRmEmptyDirs(rootDir string, except map[string]bool, checkFn func(path string) (bool, error)) ([]string, error) {
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
				return nil
			}

			dirMap[path] = true
		} else {
			for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
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

	deleted := make([]string, 0, len(emptyDirs))
	for _, emptyDir := range emptyDirs {
		full := filepath.Join(rootDir, emptyDir)
		allow := true
		if checkFn != nil {
			var err error
			allow, err = checkFn(emptyDir)
			if err != nil {
				return deleted, err
			}
		}
		if !allow {
			continue
		}
		if err := os.Remove(full); err != nil {
			return deleted, fmt.Errorf("failed to delete empty dir %s: %w", emptyDir, err)
		}
		deleted = append(deleted, emptyDir)
	}

	return deleted, nil
}

// cleanup removes every file under sesamRoot that is not in the git index.
// `.sesam/` and `.git/` are skipped entirely The intent is to wipe stale
// revealed plaintext (which is gitignored and therefore "untracked") before a
// smudge pass repopulates the worktree from sealed objects, so files removed
// in the new tree do not linger as readable plaintext.
//
// Tracked files are preserved even when modified; symlinks and other
// non-regular entries are left alone. The optional exclude list holds
// absolute paths that must not be deleted even if untracked — intended for
// identity files that happen to live inside the worktree.
func cleanup(
	repo *git.Repository,
	sesamDir string,
	checkFn func(path string) (bool, error),
	exclude ...string,
) error {
	var err error
	sesamDir, err = filepath.Abs(sesamDir)
	if err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(sesamDir, sesamSuffix)); err != nil {
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
			if name == gitSuffix {
				return filepath.SkipDir
			}
			if name == sesamSuffix {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		rel, err := filepath.Rel(sesamDir, path)
		if err != nil {
			return fmt.Errorf("rel path: %w", err)
		}

		if _, ok := tracked[rel]; ok {
			return nil
		}

		if excluded[path] {
			return nil
		}

		allow := true
		if checkFn != nil {
			allow, err = checkFn(rel)
			if err != nil {
				return err
			}
		}

		if allow {
			if err := os.Remove(path); err != nil { //nolint:gosec
				return fmt.Errorf("remove %s: %w", path, err)
			}
			slog.Debug("clean: removed untracked file", slog.String("path", rel))
		}
		return nil
	}); err != nil {
		return err
	}

	// Deleting might have created some empty dirs. Make sure we delete them
	// too, except for the .sesam/ and .git/ skeletons. checkFn gates each
	// removal so --dry-run preserves pre-existing empty directories.
	_, err = recursiveRmEmptyDirs(sesamDir, map[string]bool{
		sesamSuffix: true,
		gitSuffix:   true,
	}, checkFn)
	return err
}
