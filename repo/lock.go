package repo

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// acquireLock grabs `<sesamDir>/.sesam.lock` for the lifetime of the Repo,
// released by Close.
//
// The lock deliberately lives *outside* `.sesam/`: every mutating operation
// atomically swaps the whole `.sesam` directory (see stage.go), and a lock
// file inside it would get a fresh inode on every swap, breaking flock's
// per-inode mutual exclusion. Keeping it a sibling gives it a stable inode.
func (r *Repo) acquireLock() error {
	lockPath := filepath.Join(r.sesamDir, sesamLockName)
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
