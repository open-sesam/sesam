package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

const defaultRepoLockTimeout = 5 * time.Second

func withRepoLock(sesamDir string, fn func() error) error {
	lockPath := filepath.Join(sesamDir, ".sesam", "lock")
	lockDir := filepath.Dir(lockPath)

	if _, err := os.Stat(lockDir); err != nil {
		if os.IsNotExist(err) {
			return fn()
		}

		return fmt.Errorf("failed to access lock directory %s: %w", lockDir, err)
	}

	acquired, err := acquireRepoLock(lockPath, defaultRepoLockTimeout)
	if err != nil {
		return err
	}

	defer func() {
		err = acquired.Unlock()
		if err != nil {
			slog.Error("failed to unlock repository", slog.Any("err", err))
		}
	}()

	return fn()
}

func acquireRepoLock(lockPath string, timeout time.Duration) (*flock.Flock, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fl := flock.New(lockPath)
	locked, err := fl.TryLockContext(ctx, 150*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire repository lock %s: %w", lockPath, err)
	}

	if !locked {
		return nil, fmt.Errorf("repository is locked by another sesam process (%s)", lockPath)
	}

	return fl, nil
}
