//go:build !unix

package commands

import "syscall"

// detachedProcAttr has no portable equivalent outside unix; the unclip child
// stays in the parent's process group there.
func detachedProcAttr() *syscall.SysProcAttr {
	return nil
}
