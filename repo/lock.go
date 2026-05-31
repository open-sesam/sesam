package repo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// acquireLock grabs `.sesam/lock` for the lifetime of the Repo. Released by
// Close. Requires `.sesam/` to already exist; Init creates it first.
func (r *Repo) acquireLock() error {
	lockPath := filepath.Join(r.sesamDir, sesamSuffix, "lock")
	lockDir := filepath.Dir(lockPath)

	if _, err := os.Stat(lockDir); err != nil {
		return fmt.Errorf("sesam directory missing at %s: %w", lockDir, err)
	}

	fl, err := acquireRepoLock(lockPath, r.opts.lockTimeout())
	if err != nil {
		return err
	}
	r.lock = fl
	return nil
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
