package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// AddSecrets adds the secret(s) at path — a single file or a directory — to
// the repository's config files.
//
// For a single file:
//   - if it sits in the same directory as the main sesam.yml it is added to
//     the main file;
//   - if it sits in a subdirectory, ownSesamFile decides: when true a
//     sesam.yml is created in (or reused from) the file's directory and
//     included from the main file; when false the secret is added straight to
//     the main file (its Path keeping the subdirectory prefix).
//
// For a directory, ownSesamFile decides how its contents are laid out:
//   - true: every subdirectory gets its own sesam.yml, chained back to the
//     main file via include entries; files next to the main sesam.yml are
//     added to the main file.
//   - false: every file in the directory and all of its subdirectories is
//     added straight to the main sesam.yml, each Path kept relative to the
//     main file's directory. No per-directory sesam.yml or include is created.
//
// Dotfiles and the special name `.git` are skipped. Per-file metadata
// (type/access/description) is left empty — the user fills it in afterwards.
// Re-running is idempotent: existing entries (matched by Path / include path)
// are left alone, new files are appended.
//
// It returns the absolute on-disk paths of the secrets that were newly added
// (existing entries, skipped for idempotency, are not included) so the caller
// can mirror the change into the secret manager.
func (c *ConfigRepository) AddSecrets(path string, nested bool, access []string) ([]string, error) {
	// Resolve to absolute so the path lines up with the (absolute) source-file
	// paths the layout logic records and reports — both addSecretsFile's Rel and
	// the returned revealed paths assume this.
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve secret path %q: %w", path, err)
	}

	// TODO: an already included secret should give back an error with where the secret is already added (path to this sesam.yml)
	before := c.trackedRevealedPaths()

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		err = c.addSecretsDir(path, nested, access)
	} else {
		err = c.addSecretsFile(path, nested, access)
	}
	if err != nil {
		return nil, err
	}

	after := c.trackedRevealedPaths()

	var added []string
	for p := range after {
		if !before[p] {
			added = append(added, p)
		}
	}
	slices.Sort(added)

	return added, nil
}

// addSecretsDir lays out a directory's secrets according to ownSesamFile.
// When false, every file (recursively) is flattened into the main sesam.yml.
// When true, each subdirectory gets its own sesam.yml: the recursion writes
// straight into MainFile when dirPath is the main file's own directory (no
// include to add), otherwise dirPath/sesam.yml is referenced from MainFile.
func (c *ConfigRepository) addSecretsDir(dirPath string, nested bool, access []string) error {
	if !nested {
		return c.addSecretsFlat(dirPath, access)
	}

	sesamPath, err := c.addSecretsRecursive(dirPath, access)
	if err != nil {
		return err
	}

	if sesamPath == "" || sesamPath == c.MainFile.Path {
		return nil
	}

	return c.includeFromMain(sesamPath)
}

// addSecretsFlat walks dirPath recursively and adds every eligible file
// straight to the main sesam.yml, each Path kept relative to the main file's
// directory. Dotfiles/dot-directories (including .git) are skipped, as is any
// nested sesam.yml. No per-directory sesam.yml or include entry is created.
func (c *ConfigRepository) addSecretsFlat(dirPath string, access []string) error {
	mainDir := filepath.Dir(c.MainFile.Path)

	return filepath.WalkDir(dirPath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip dot entries below the root; the explicitly-given root is kept
		// even if its own name starts with a dot.
		if p != dirPath && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() || d.Name() == "sesam.yml" {
			return nil
		}

		rel, err := filepath.Rel(mainDir, p)
		if err != nil {
			return err
		}

		return c.addSecret(c.MainFile, rel, access)
	})
}

// addSecretsFile adds one file. Files next to the main sesam.yml (or any file
// when ownSesamFile is false) land in the main file; otherwise the file's
// directory gets its own sesam.yml, included from the main file.
func (c *ConfigRepository) addSecretsFile(filePath string, nested bool, access []string) error {
	// Already tracked by some sesam.yml: adding it again is a no-op. Bail before
	// creating a sub-file/include for a secret we would only skip.
	if c.trackedRevealedPaths()[filepath.Clean(filePath)] {
		return nil
	}

	mainDir := filepath.Dir(c.MainFile.Path)
	fileDir := filepath.Dir(filePath)

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

	// Path is recorded relative to its own sesam.yml's directory.
	abs, err := filepath.Abs(filepath.Dir(src.Path))
	if err != nil {
		return err
	}

	rel, err := filepath.Rel(abs, filePath)
	if err != nil {
		return err
	}

	return c.addSecret(src, rel, access)
}

// includeFromMain adds an include of sesamPath to MainFile, unless one is
// already present.
func (c *ConfigRepository) includeFromMain(sesamPath string) error {
	incPath, err := filepath.Rel(filepath.Dir(c.MainFile.Path), sesamPath)
	if err != nil {
		return err
	}

	if slices.Contains(fileIncludes(c.MainFile.RootNode), incPath) {
		return nil
	}

	return c.appendInclude(c.MainFile, incPath)
}

// addSecret inserts a secret node owned by src with the given relative path,
// unless the physical file it points at is already tracked by some sesam.yml
// (src itself or any other loaded file). This keeps a secret from being written
// twice — including the case where a file already declared in a sub-file would
// otherwise be re-added to the main file, or vice versa.
func (c *ConfigRepository) addSecret(src *FileSource, relPath string, access []string) error {
	abs := filepath.Join(filepath.Dir(src.Path), relPath)
	if c.trackedRevealedPaths()[abs] {
		return nil
	}

	return appendSecretsItems(src, []Secret{{Path: relPath, Access: access}})
}

// addSecretsRecursive processes one directory: recurses into subdirs first
// (so their sesam.yml exists before we reference it), then ensures
// dirPath/sesam.yml exists and contains entries for every discovered file
// and every produced subdirectory include. Returns the path to
// dirPath/sesam.yml or "" if the directory had no eligible content.
func (c *ConfigRepository) addSecretsRecursive(dirPath string, access []string) (string, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return "", err
	}

	var files []string
	var subDirs []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}

		if !entry.IsDir() && name == "sesam.yml" {
			continue
		}

		if entry.IsDir() {
			subDirs = append(subDirs, name)
		} else {
			files = append(files, name)
		}
	}

	var includeRels []string
	for _, subDir := range subDirs {
		subPath, err := c.addSecretsRecursive(filepath.Join(dirPath, subDir), access)
		if err != nil {
			return "", err
		}

		if subPath == "" {
			continue
		}

		rel, err := filepath.Rel(dirPath, subPath)
		if err != nil {
			return "", err
		}

		includeRels = append(includeRels, rel)
	}

	if len(files) == 0 && len(includeRels) == 0 {
		return "", nil
	}

	sesamPath := filepath.Join(dirPath, "sesam.yml")
	src, err := c.loadOrCreate(sesamPath)
	if err != nil {
		return "", err
	}

	for _, name := range files {
		if err := c.addSecret(src, name, access); err != nil {
			return "", err
		}
	}

	seenIncludes := map[string]bool{}
	for _, inc := range fileIncludes(src.RootNode) {
		seenIncludes[inc] = true
	}

	for _, inc := range includeRels {
		if seenIncludes[inc] {
			continue
		}
		if err := c.appendInclude(src, inc); err != nil {
			return "", err
		}
	}

	return sesamPath, nil
}

// loadOrCreate returns the FileSource for `path`, loading it (and every file it
// includes) from disk if it exists, or bootstrapping an empty in-memory
// FileSource that Save() will write out once it has its first item.
func (c *ConfigRepository) loadOrCreate(path string) (*FileSource, error) {
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
func (c *ConfigRepository) newFile(path string) *FileSource {
	src := &FileSource{Path: path}
	c.SourceFiles[path] = src
	return src
}

// appendInclude inserts an include node pointing at includePath into src's
// secrets sequence.
func (c *ConfigRepository) appendInclude(src *FileSource, includePath string) error {
	return appendSecretsItems(src, []Secret{{Include: includePath}})
}
