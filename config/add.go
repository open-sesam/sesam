package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// AddSecret adds (or updates) a single secret file in the configuration.
//
// It is a self-deciding upsert: if the file is already tracked by some
// sesam.yml the call is treated as an access-group change (delegating to
// ChangeSecretGroups); otherwise the secret is inserted.
//
// Where a newly inserted secret lands depends on nested:
//   - false: the secret is added straight to the main sesam.yml, its Path kept
//     relative to the main file's directory (subdirectory prefix preserved).
//   - true: a file in a subdirectory gets its own sesam.yml in that directory
//     (created or reused) and included from the main file; its Path is recorded
//     relative to that sub-file. A file next to the main sesam.yml always lands
//     in the main file regardless of nested.
//
// Directory expansion is the caller's job (repo): AddSecret only ever touches a
// single file. Per-file metadata other than access is left empty for the user
// to fill in.
func (c *Config) AddSecret(path string, nested bool, access []string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to resolve secret path %q: %w", path, err)
	}
	abs = filepath.Clean(abs)

	// Self-deciding: an already-tracked file is an access change, not an add.
	// This also keeps a file from being declared twice — including the case
	// where it was first added to a sub-file and is now re-added to the main
	// file, or vice versa.
	if c.trackedRevealedPaths()[abs] {
		return c.changeSecretGroups(abs, access)
	}

	return c.placeSecret(abs, nested, Secret{Access: access})
}

// placeSecret inserts a brand-new secret for the on-disk file at abs into the
// appropriate sesam.yml, honoring nested (see AddSecret). The caller supplies
// the secret's metadata (access, description, …); placeSecret fills in Path
// relative to the owning file's directory. abs must not already be tracked.
func (c *Config) placeSecret(abs string, nested bool, sec Secret) error {
	mainDir := filepath.Dir(c.MainFile.Path)
	fileDir := filepath.Dir(abs)

	src := c.MainFile
	if nested && !sameDir(fileDir, mainDir) {
		sesamPath := filepath.Join(fileDir, "sesam.yml")
		s, err := c.loadOrCreate(sesamPath)
		if err != nil {
			return err
		}

		if err := c.includeFromMain(sesamPath); err != nil {
			return err
		}

		src = s
	}

	rel, err := filepath.Rel(filepath.Dir(src.Path), abs)
	if err != nil {
		return err
	}

	sec.Path = rel
	return appendSecretsItems(src, []Secret{sec})
}

// includeFromMain adds an include of sesamPath to MainFile, unless one is
// already present.
func (c *Config) includeFromMain(sesamPath string) error {
	incPath, err := filepath.Rel(filepath.Dir(c.MainFile.Path), sesamPath)
	if err != nil {
		return err
	}

	if slices.Contains(fileIncludes(c.MainFile.RootNode), incPath) {
		return nil
	}

	return c.appendInclude(c.MainFile, incPath)
}

// loadOrCreate returns the FileSource for `path`, loading it (and every file it
// includes) from disk if it exists, or bootstrapping an empty in-memory
// FileSource that Save() will write out once it has its first item.
func (c *Config) loadOrCreate(path string) (*FileSource, error) {
	if existing, ok := c.SourceFiles[path]; ok {
		return existing, nil
	}

	if _, err := os.Stat(path); err == nil {
		return c.loadTree(path)
	}

	return c.newFile(path), nil
}

// newFile registers an in-memory FileSource for a path that doesn't exist on
// disk yet. Its RootNode stays nil until the first secret/include is added,
// which builds the document; Save writes it like any other file.
func (c *Config) newFile(path string) *FileSource {
	src := &FileSource{Path: path}
	c.SourceFiles[path] = src
	return src
}

// appendInclude inserts an include node pointing at includePath into src's
// secrets sequence.
func (c *Config) appendInclude(src *FileSource, includePath string) error {
	return appendSecretsItems(src, []Secret{{Include: includePath}})
}
