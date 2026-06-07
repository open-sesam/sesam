package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
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
func (c *ConfigRepository) AddSecrets(path string, ownSesamFile bool, access []string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return c.addSecretsDir(path, ownSesamFile, access)
	}

	return c.addSecretsFile(path, ownSesamFile, access)
}

// addSecretsDir lays out a directory's secrets according to ownSesamFile.
// When false, every file (recursively) is flattened into the main sesam.yml.
// When true, each subdirectory gets its own sesam.yml: the recursion writes
// straight into MainFile when dirPath is the main file's own directory (no
// include to add), otherwise dirPath/sesam.yml is referenced from MainFile.
func (c *ConfigRepository) addSecretsDir(dirPath string, ownSesamFile bool, access []string) error {
	if !ownSesamFile {
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

		c.addSecret(c.MainFile, rel, access)
		return nil
	})
}

// addSecretsFile adds one file. Files next to the main sesam.yml (or any file
// when ownSesamFile is false) land in the main file; otherwise the file's
// directory gets its own sesam.yml, included from the main file.
func (c *ConfigRepository) addSecretsFile(filePath string, ownSesamFile bool, access []string) error {
	mainDir := filepath.Dir(c.MainFile.Path)
	fileDir := filepath.Dir(filePath)

	src := c.MainFile
	if ownSesamFile && !sameDir(fileDir, mainDir) {
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
	rel, err := filepath.Rel(filepath.Dir(src.Path), filePath)
	if err != nil {
		return err
	}

	c.addSecret(src, rel, access)
	return nil
}

// includeFromMain queues an include of sesamPath in MainFile, unless one is
// already present.
func (c *ConfigRepository) includeFromMain(sesamPath string) error {
	incPath, err := filepath.Rel(filepath.Dir(c.MainFile.Path), sesamPath)
	if err != nil {
		return err
	}

	if slices.Contains(c.MainFile.allIncludes(), incPath) {
		return nil
	}

	c.appendInclude(c.MainFile, incPath)
	return nil
}

// addSecret appends a Secret owned by src with the given relative path, unless
// an identical entry already exists.
func (c *ConfigRepository) addSecret(src *FileSource, relPath string, access []string) {
	for _, s := range c.MainFile.Config.Secrets {
		if s.Source == src && s.Path == relPath {
			return
		}
	}

	c.MainFile.Config.Secrets = append(c.MainFile.Config.Secrets, Secret{
		Path:   relPath,
		Source: src,
		Access: access,
	})
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

	seenPaths := map[string]bool{}
	for _, s := range c.MainFile.Config.Secrets {
		if s.Source == src && s.Path != "" {
			seenPaths[s.Path] = true
		}
	}

	seenIncludes := map[string]bool{}
	for _, inc := range src.allIncludes() {
		seenIncludes[inc] = true
	}

	for _, name := range files {
		if seenPaths[name] {
			continue
		}

		c.MainFile.Config.Secrets = append(c.MainFile.Config.Secrets, Secret{
			Path:   name,
			Source: src,
			Access: access,
		})
	}

	for _, inc := range includeRels {
		if seenIncludes[inc] {
			continue
		}
		c.appendInclude(src, inc)
	}

	return sesamPath, nil
}

// loadOrCreate returns the FileSource for `path`, loading it from disk if it
// exists (and integrating its secrets into MainFile.Config.Secrets) or
// bootstrapping an empty in-memory FileSource that Save() will write out.
func (c *ConfigRepository) loadOrCreate(path string) (*FileSource, error) {
	if existing, ok := c.SourceFiles[path]; ok {
		return existing, nil
	}

	if _, err := os.Stat(path); err == nil {
		src, err := c.loadFile(path)
		if err != nil {
			return nil, err
		}

		c.SourceFiles[path] = src
		flat, err := c.resolveSource(src)
		if err != nil {
			return nil, err
		}

		c.MainFile.Config.Secrets = append(c.MainFile.Config.Secrets, flat...)
		return src, nil
	}

	return c.newFile(path), nil
}

// newFile registers an in-memory FileSource for a path that doesn't exist
// on disk yet. Its RootNode stays nil; Save uses writeFreshFile for these.
func (c *ConfigRepository) newFile(path string) *FileSource {
	src := &FileSource{
		Path:       path,
		CommentMap: yaml.CommentMap{},
		Config:     &Config{},
	}

	c.SourceFiles[path] = src
	return src
}

// appendInclude queues a new include path on src; Save appends it on the
// next write.
func (c *ConfigRepository) appendInclude(src *FileSource, includePath string) {
	src.NewIncludes = append(src.NewIncludes, includePath)
}
