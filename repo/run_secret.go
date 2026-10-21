//go:build !linux

package repo

import "os"

// runSecretFile unlinks an empty file before writing any plaintext. Only the
// read-only descriptor is inherited; the kernel owns the file's lifetime.
func runSecretFile(content []byte) (_ *os.File, err error) {
	writer, err := os.CreateTemp("", "sesam-run-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = writer.Close() }()
	reader, err := os.Open(writer.Name())
	if err != nil {
		_ = os.Remove(writer.Name())
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = reader.Close()
		}
	}()
	if err := os.Remove(writer.Name()); err != nil {
		return nil, err
	}
	if err := writer.Chmod(0o400); err != nil {
		return nil, err
	}
	if _, err := writer.Write(content); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return reader, nil
}
