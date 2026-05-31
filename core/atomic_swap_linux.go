//go:build linux

package core

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// atomicSwapDirs atomically swaps the contents of the directories at `a`
// and `b`. After a successful call, the directory entry that was reachable
// at `a` is reachable at `b` and vice versa, in a single kernel-atomic
// operation (renameat2 with RENAME_EXCHANGE, Linux >= 3.15).
//
// Both paths must exist and reside on the same filesystem.
func atomicSwapDirs(a, b string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE); err != nil {
		return fmt.Errorf("renameat2(EXCHANGE) %s <-> %s: %w", a, b, err)
	}
	return nil
}
