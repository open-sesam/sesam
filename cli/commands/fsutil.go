package commands

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sahib/renameio/v2"
)

// untar writes the archive below destDir, dropping `strip` from every path so a
// nested directory lands at the root of the extraction.
func untar(rd io.Reader, destDir, strip string) error {
	root, err := makeRoot(destDir)
	if err != nil {
		return err
	}

	defer func() { _ = root.Close() }()

	tr := tar.NewReader(rd)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		name := strings.TrimPrefix(filepath.ToSlash(hdr.Name), strip+"/")
		if name == "" || name == "." {
			// git archive emits an entry for the prefix directory itself.
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
				return err
			}

			fd, err := root.Create(name)
			if err != nil {
				return err
			}

			//nolint:gosec // archive comes from our own git repo.
			if _, err := io.Copy(fd, tr); err != nil {
				_ = fd.Close()
				return err
			}

			if err := fd.Close(); err != nil {
				return err
			}
		}
	}
}

// makeRoot creates dir if needed and opens it as a root, so everything written
// below it stays below it.
func makeRoot(dir string) (*os.Root, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	return os.OpenRoot(dir)
}

func writeJSONFile(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return renameio.WriteFile(path, data, 0o600)
}
