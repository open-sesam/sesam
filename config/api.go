package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
)

// AddSecret appends a single secret to the main file.
func (c *ConfigRepository) AddSecret(secret Secret) error {
	secret.Source = c.MainFile
	c.MainFile.Config.Secrets = append(c.MainFile.Config.Secrets, secret)
	return nil
}

// AddSecretDir walks dirPath and ensures every directory it visits has its
// own sesam.yml containing one Secret per eligible file plus an `include:`
// for every subdirectory that itself produced a sesam.yml. The top-level
// dirPath/sesam.yml is referenced from MainFile via a new include entry.
//
// Dotfiles and the special name `.git` are skipped. Per-file metadata
// (type/access/description) is left empty — the user fills it in afterwards.
// Re-running on the same directory is idempotent: existing entries (matched
// by Path / include path) are left alone, new files are appended.
func (c *ConfigRepository) AddSecretDir(dirPath string) error {
	sesamPath, err := c.addSecretsRecursive(dirPath)
	if err != nil {
		return err
	}

	if sesamPath == "" {
		return nil
	}

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

// addSecretsRecursive processes one directory: recurses into subdirs first
// (so their sesam.yml exists before we reference it), then ensures
// dirPath/sesam.yml exists and contains entries for every discovered file
// and every produced subdirectory include. Returns the path to
// dirPath/sesam.yml or "" if the directory had no eligible content.
func (c *ConfigRepository) addSecretsRecursive(dirPath string) (string, error) {
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
		subPath, err := c.addSecretsRecursive(filepath.Join(dirPath, subDir))
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
			Name:   name,
			Path:   name,
			Source: src,
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
		src, err := loadFile(path)
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
