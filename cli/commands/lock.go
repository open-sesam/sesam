package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func withRepoLock(repoRoot string, timeout time.Duration, fn func() error) error {
	lockPath := filepath.Join(repoRoot, ".sesam", "lock")
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
		_ = acquired.Close()
		_ = os.Remove(lockPath)
	}()

	return fn()
}

func acquireRepoLock(lockPath string, timeout time.Duration) (*os.File, error) {
	deadline := time.Now().Add(timeout)
	for {
		//nolint:gosec
		fd, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(fd, "pid=%d\ntime=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
			return fd, nil
		}

		if !os.IsExist(err) {
			return nil, fmt.Errorf("failed to acquire repository lock %s: %w", lockPath, err)
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("repository is locked by another sesam process (%s); remove only if you are sure no sesam process is running", lockPath)
		}

		time.Sleep(150 * time.Millisecond)
	}
}
