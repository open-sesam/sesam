//go:build !linux

package repo

import (
	"fmt"
	"os"
)

// atomicSwapDirs swaps the contents of `a` and `b` using a three-rename
// dance via a sibling tmp path. This is NOT FULLY atomic: there is a brief
// window in which `a` and `b` do not exist at their original locations.
// On Linux a true atomic implementation backed by renameat2(RENAME_EXCHANGE)
// is used instead; see atomic_swap_linux.go.
//
// Both paths must exist and reside on the same filesystem.
func atomicSwapDirs(a, b string) error {
	tmp := a + ".swap"
	// Defensive: a previous crash mid-swap may have left `tmp` behind.
	_ = os.RemoveAll(tmp)

	if err := os.Rename(a, tmp); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", a, tmp, err)
	}
	if err := os.Rename(b, a); err != nil {
		_ = os.Rename(tmp, a) // best-effort restore of the original a
		return fmt.Errorf("rename %s -> %s: %w", b, a, err)
	}
	if err := os.Rename(tmp, b); err != nil {
		// `a` is already the new tree; don't strand the old one at tmp.
		_ = os.RemoveAll(tmp)
	}
	return nil
}
