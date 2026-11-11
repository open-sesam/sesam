package config

import (
	"fmt"
	"path/filepath"
)

// SecretAdd adds (or updates) a single secret file in the configuration.
//
// If the file is already tracked by some
// sesam.yml the call is treated as an access-group change (delegating to
// SecretChangeGroups); otherwise the secret is inserted.
//
// Where a newly inserted secret lands depends on nested:
//   - false: the secret is added to the nearest loaded sesam.yml at or above
//     its directory (the main file if no sub-config covers it).
//   - true: a file in a subdirectory gets its own sesam.yml in that directory
//     (created or reused). A file next to the main sesam.yml always lands in
//     the main file regardless of nested.
//
// Either way its Path is recorded relative to the owning file's directory.
//
// Directory expansion is the caller's job (repo): SecretAdd only ever touches a
// single file. Per-file metadata other than access is left empty for the user
// to fill in.
func (c *Config) SecretAdd(path string, nested bool, access []string) error {
	rel := filepath.Clean(path)
	tracked, err := c.trackedRevealedPaths()
	if err != nil {
		return err
	}

	if tracked[rel] {
		if len(access) == 0 {
			// if no groups change and secret exists, we assume no change requested.
			// If [admin] is given explicitly we would set it explicitly.
			return nil
		}

		return c.changeSecretGroups(rel, access)
	}

	return c.placeSecret(rel, nested, Secret{Access: access})
}

// placeSecret inserts a brand-new secret for the on-disk file at abs into the
// appropriate sesam.yml. The caller supplies the secret's metadata (access, description, …)
// placeSecret fills in Path relative to the owning file's directory. abs must not already be tracked.
func (c *Config) placeSecret(rel string, nested bool, sec Secret) error {
	mainDir := filepath.Dir(c.MainFile.Path)
	fileDir := filepath.Dir(rel)

	src := c.nearestSource(fileDir)
	if nested && !sameDir(fileDir, mainDir) {
		src = c.sourceFor(filepath.Join(fileDir, "sesam.yml"))
	}

	secRel, err := filepath.Rel(filepath.Dir(src.Path), rel)
	if err != nil {
		return fmt.Errorf("failed to locate %q under %q: %w", rel, filepath.Dir(src.Path), err)
	}

	sec.Path = secRel
	return appendSecretsItems(src, []Secret{sec})
}

// nearestSource returns the loaded config file whose directory is the closest
// ancestor of (or equal to) dir, falling back to MainFile.
func (c *Config) nearestSource(dir string) *FileSource {
	mainDir := filepath.Dir(c.MainFile.Path)
	for {
		if sameDir(dir, mainDir) {
			return c.MainFile
		}
		if src, ok := c.SourceFiles[filepath.Join(dir, "sesam.yml")]; ok {
			return src
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return c.MainFile
		}
		dir = parent
	}
}

// sourceFor returns the FileSource for path, registering an empty in-memory
// one that Save() will write out once it has its first item. Every sub-config
// on disk was already loaded by Load, so a miss means the file is new.
func (c *Config) sourceFor(path string) *FileSource {
	if existing, ok := c.SourceFiles[path]; ok {
		return existing
	}
	return c.newFile(path)
}

// newFile registers an in-memory FileSource for a path that doesn't exist on
// disk yet. Its RootNode stays nil until the first secret is added,
// which builds the document; Save writes it like any other file.
func (c *Config) newFile(path string) *FileSource {
	src := &FileSource{Path: path}
	c.SourceFiles[path] = src
	return src
}

// sameDir reports whether a and b refer to the same directory.
func sameDir(a, b string) bool {
	rel, err := filepath.Rel(a, b)
	return err == nil && rel == "."
}
