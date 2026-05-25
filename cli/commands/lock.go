package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

func withRepoLock(sesamDir string, timeout time.Duration, fn func() error) (err error) {
	if timeout <= 0 {
		return fmt.Errorf("invalid lock timeout %s: must be > 0", timeout)
	}

	lockPath := filepath.Join(sesamDir, ".sesam", "lock")
	lockDir := filepath.Dir(lockPath)

	if _, err := os.Stat(lockDir); err != nil {
		if os.IsNotExist(err) {
			return fn()
		}

		return fmt.Errorf("failed to access lock directory %s: %w", lockDir, err)
	}

	acquired, err := acquireRepoLock(lockPath, timeout)
	if err != nil {
		return err
	}

	defer func() {
		unlockErr := acquired.Unlock()
		if unlockErr != nil && err == nil {
			err = fmt.Errorf("failed to unlock repository: %w", unlockErr)
		}
	}()

	err = fn()
	return err
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
