package repo

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// runSecretFile streams plaintext into an anonymous memory file. Sealing makes
// it immutable even when reopened via /dev/fd.
func runSecretFile(write func(io.Writer) error) (_ *os.File, err error) {
	fd, err := unix.MemfdCreate("sesam-run", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "sesam-run")
	defer func() {
		if err != nil {
			_ = file.Close()
		}
	}()
	if err := write(file); err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err := file.Chmod(0o400); err != nil {
		return nil, err
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return nil, err
	}
	return file, nil
}
