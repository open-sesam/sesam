package repo

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/sahib/renameio/v2"
	"opensesam.org/sesam/core"
)

// EditSecret reveals one secret to .sesam/tmp, runs edit on that file, copies
// the result back into the worktree, and seals the repository.
func (r *Repo) EditSecret(revealedPath string, edit func(path string) error, sealAll bool) error {
	if edit == nil {
		return fmt.Errorf("missing editor")
	}

	tmpPath, err := r.revealSecretToTmp(revealedPath)
	if err != nil {
		return err
	}
	defer func() { _ = r.root.Remove(tmpPath) }()

	if err := edit(filepath.Join(r.sesamDir, tmpPath)); err != nil {
		return err
	}
	if err := r.copyEditedSecret(tmpPath, revealedPath); err != nil {
		return err
	}

	return r.Update(func(s *Stage) error {
		return s.Seal(sealAll)
	})
}

func (r *Repo) revealSecretToTmp(revealedPath string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return "", ErrClosed
	}
	if _, ok := r.vstate.SecretExists(revealedPath); !ok {
		return "", fmt.Errorf("no such secret: %s", revealedPath)
	}

	tmpPath := filepath.Join(core.SesamTmpDir(), revealedPath)
	if err := r.secret.RevealTo(revealedPath, tmpPath); err != nil {
		return "", fmt.Errorf("failed to reveal %s: %w", revealedPath, err)
	}
	return tmpPath, nil
}

func (r *Repo) copyEditedSecret(tmpPath, revealedPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}
	if err := r.root.MkdirAll(filepath.Dir(revealedPath), 0o700); err != nil {
		return fmt.Errorf("create revealed dir: %w", err)
	}

	src, err := r.root.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("open edited secret: %w", err)
	}
	defer func() { _ = src.Close() }()

	dst, err := renameio.NewPendingFile(
		revealedPath,
		renameio.WithRoot(r.root),
		renameio.WithTempDir(core.SesamTmpDir()),
		renameio.WithPermissions(0o600),
	)
	if err != nil {
		return fmt.Errorf("create revealed file: %w", err)
	}
	defer func() { _ = dst.Cleanup() }()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy edited secret: %w", err)
	}
	_ = dst.Chmod(0o600)
	if err := dst.CloseAtomicallyReplace(); err != nil {
		return fmt.Errorf("replace revealed file: %w", err)
	}
	return nil
}
