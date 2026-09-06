//go:build unix

package commands

import "syscall"

// detachedProcAttr puts the unclip child into its own process group, so a
// Ctrl+C in the terminal that ran `sesam show --clip` does not take the
// pending clipboard clear down with it.
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
