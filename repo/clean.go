package repo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

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

	root, err := os.OpenRoot(sesamDir)
	if err != nil {
		return fmt.Errorf("open repo root %q: %w", sesamDir, err)
	}
	defer func() { _ = root.Close() }()

	return cleanup(root, gr, opts.CheckFunc, identityPaths...)
}

// deleteRevealedSecrets removes the plaintext copy on disk for every
// VerifiedSecret in `secrets`, ignoring already-absent files. checkFn, when
// non-nil, gates each removal and receives the sesam-relative path.
func deleteRevealedSecrets(root *os.Root, secrets []core.VerifiedSecret, checkFn func(path string) (bool, error)) error {
	for _, secret := range secrets {
		allow := true
		if checkFn != nil {
			var err error
			allow, err = checkFn(secret.RevealedPath)
			if err != nil {
				return err
			}
		}

		if allow {
			if err := root.Remove(secret.RevealedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("failed to delete %s: %w", secret.RevealedPath, err)
			}
		}
	}

	return nil
}

// cleanup removes every file under root that is not in the git index. `.sesam/`,
// `.git/` and the stage fork `.sesam-tmp/` are skipped entirely. The intent is
// to wipe stale revealed plaintext (which is gitignored and therefore
// "untracked") before a smudge pass repopulates the worktree from sealed
// objects, so files removed in the new tree do not linger as readable plaintext.
//
// Tracked files are preserved even when modified; symlinks and other non-regular
// entries are left alone. The optional exclude list holds absolute paths that
// must not be deleted even if untracked — intended for identity files that
// happen to live inside the worktree. All file I/O is confined to root.
func cleanup(
	root *os.Root,
	gitRepo *git.Repository,
	checkFn func(path string) (bool, error),
	exclude ...string,
) error {
	if _, err := root.Stat(sesamSuffix); err != nil {
		return fmt.Errorf("not a sesam directory %q: %w", root.Name(), err)
	}

	// Exclude paths are given as absolute (identity files). Convert to
	// root-relative for comparison against the walk; ones outside root simply
	// never match a walked entry.
	excluded := make(map[string]bool, len(exclude))
	for _, p := range exclude {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(root.Name(), abs); err == nil {
			excluded[rel] = true
		}
	}

	idx, err := gitRepo.Storer.Index()
	if err != nil {
		return fmt.Errorf("read git index: %w", err)
	}

	tracked := make(map[string]struct{}, len(idx.Entries))
	for _, e := range idx.Entries {
		tracked[filepath.FromSlash(e.Name)] = struct{}{}
	}

	if err := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel := filepath.FromSlash(p)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case gitSuffix, sesamSuffix, forkSuffix:
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		// The repo lock lives at the worktree root but is sesam-internal infra.
		if d.Name() == sesamLockName {
			return nil
		}
		if _, ok := tracked[rel]; ok {
			return nil
		}
		if excluded[rel] {
			return nil
		}

		allow := true
		if checkFn != nil {
			var err error
			allow, err = checkFn(rel)
			if err != nil {
				return err
			}
		}

		if allow {
			if err := root.Remove(rel); err != nil {
				return fmt.Errorf("remove %s: %w", rel, err)
			}
			slog.Debug("clean: removed untracked file", slog.String("path", rel))
		}
		return nil
	}); err != nil {
		return err
	}

	// Deleting might have created empty dirs; drop them too, except the
	// .sesam/ and .git/ skeletons.
	_, err = core.PruneEmptyDirs(root, ".", map[string]bool{
		sesamSuffix: true,
		gitSuffix:   true,
	}, checkFn)
	return err
}
