package repo

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAcquireRepoLock_BlocksWhileHeld(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lock")

	held, err := acquireRepoLock(lockPath, time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = held.Unlock() })

	// A second acquire on the same path with a tight timeout must fail
	// because the first one still holds it. The exact wording depends on
	// the flock backend (deadline exceeded vs "locked by another process"),
	// so we only assert the prefix wrapping that this package adds.
	second, err := acquireRepoLock(lockPath, 200*time.Millisecond)
	require.Error(t, err)
	require.Nil(t, second)
	require.Contains(t, err.Error(), "acquire repository lock")
}

func TestAcquireRepoLock_SucceedsAfterRelease(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lock")

	first, err := acquireRepoLock(lockPath, time.Second)
	require.NoError(t, err)
	require.NoError(t, first.Unlock())

	second, err := acquireRepoLock(lockPath, time.Second)
	require.NoError(t, err)
	require.NoError(t, second.Unlock())
}

func TestRepo_acquireLock_FailsWithoutSesamDir(t *testing.T) {
	dir := t.TempDir() // no .sesam/ inside

	r := &Repo{
		sesamDir: dir,
		opts:     RepoOpts{LockTimeout: time.Second},
	}

	err := r.acquireLock()
	require.Error(t, err)
	require.Contains(t, err.Error(), "sesam directory missing")
}

func TestRepo_acquireLock_HappyPath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, sesamSuffix), 0o700))

	r := &Repo{
		sesamDir: dir,
		opts:     RepoOpts{LockTimeout: time.Second},
	}

	require.NoError(t, r.acquireLock())
	require.NotNil(t, r.lock)
	require.NoError(t, r.lock.Unlock())
}
