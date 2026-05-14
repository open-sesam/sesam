package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// ConfigRepository holds every loaded file plus the merged secrets view.
// MainFile is the top level file passed to Load; it is also present in
// SourceFiles (keyed by path) so Save can iterate one map and treat every
// file uniformly.
type ConfigRepository struct {
	MainFile    *FileSource
	SourceFiles map[string]*FileSource
}

func NewConfigRepository() *ConfigRepository {
	return &ConfigRepository{
		SourceFiles: map[string]*FileSource{},
	}
}

// Load is the entry function for ConfigRepository. Main sesam.yml file
// should be passed to Load.
func (c *ConfigRepository) Load(path string) error {
	src, err := loadFile(path)
	if err != nil {
		return err
	}

	c.MainFile = src
	c.SourceFiles[path] = src
	return nil
}

func loadFile(path string) (*FileSource, error) {
	root, cm, err := readYAMLFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	if err := yaml.NodeToValue(root, cfg); err != nil {
		return nil, err
	}

	return &FileSource{
		Path:       path,
		RootNode:   root,
		CommentMap: cm,
		Config:     cfg,
	}, nil
}

func readYAMLFile(path string) (ast.Node, yaml.CommentMap, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	cm := yaml.CommentMap{}
	decoder := yaml.NewDecoder(f, yaml.CommentToMap(cm))

	var root ast.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, nil, err
	}

	return root, cm, nil
}

// Resolve walks the main file's secrets sequence plus every transitively
// included file, replaces MainFile.Config.Secrets with the merged flat list,
// and sets each Secret.Source back-pointer to the file it came from. Each
// FileSource records its include placeholders so Save can re-emit them.
func (c *ConfigRepository) Resolve() error {
	flat, err := c.resolveSource(c.MainFile)
	if err != nil {
		return err
	}

	c.MainFile.Config.Secrets = flat
	return nil
}

func (c *ConfigRepository) resolveSource(src *FileSource) ([]Secret, error) {
	seq, err := secretsNode(src.RootNode)
	if err != nil {
		return nil, err
	}

	var flat []Secret
	for i, item := range seq.Values {
		mapNode, ok := item.(*ast.MappingNode)
		if !ok {
			return nil, fmt.Errorf("%s: secrets[%d] is not a mapping (got %T)", src.Path, i, item)
		}

		if inc, ok := includePath(mapNode); ok {
			path := filepath.Join(filepath.Dir(src.Path), inc)
			sub, err := loadFile(path)
			if err != nil {
				return nil, fmt.Errorf("loading include %s: %w", path, err)
			}

			c.SourceFiles[path] = sub

			subSecrets, err := c.resolveSource(sub)
			if err != nil {
				return nil, err
			}
			flat = append(flat, subSecrets...)
			continue
		}

		var s Secret
		if err := yaml.NodeToValue(mapNode, &s); err != nil {
			return nil, fmt.Errorf("%s: decoding secrets[%d]: %w", src.Path, i, err)
		}

		s.Source = src
		s.node = mapNode
		flat = append(flat, s)
	}

	return flat, nil
}

// allIncludes returns every include path attached to this file — both ones
// currently in the AST and ones queued in NewIncludes.
func (s *FileSource) allIncludes() []string {
	var paths []string
	if s.RootNode != nil {
		if seq, err := secretsNode(s.RootNode); err == nil && seq != nil {
			for _, item := range seq.Values {
				m, ok := item.(*ast.MappingNode)
				if !ok {
					continue
				}
				if inc, ok := includePath(m); ok {
					paths = append(paths, inc)
				}
			}
		}
	}
	return append(paths, s.NewIncludes...)
}

// secretsNode returns the *ast.SequenceNode at root.config.secrets, or an
// error if the structure doesn't match.
func secretsNode(root ast.Node) (*ast.SequenceNode, error) {
	mv, err := findSecretsValue(root)
	if err != nil {
		return nil, err
	}

	seq, ok := mv.Value.(*ast.SequenceNode)
	if !ok {
		return nil, fmt.Errorf("expected sequence under config.secrets, got %T", mv.Value)
	}

	return seq, nil
}

// findSecretsValue returns the MappingValueNode whose key is "secrets"
// inside the root mapping's "config:" entry, or an error if absent.
func findSecretsValue(root ast.Node) (*ast.MappingValueNode, error) {
	rootMap, ok := root.(*ast.MappingNode)
	if !ok {
		return nil, fmt.Errorf("expected mapping at root, got %T", root)
	}

	for _, mv := range rootMap.Values {
		if mv.Key.String() != "config" {
			continue
		}

		cfg, ok := mv.Value.(*ast.MappingNode)
		if !ok {
			return nil, fmt.Errorf("expected mapping under config, got %T", mv.Value)
		}

		for _, cv := range cfg.Values {
			if cv.Key.String() == "secrets" {
				return cv, nil
			}
		}

		return nil, fmt.Errorf("no secrets: key in root")
	}

	return nil, fmt.Errorf("no config: key in root")
}

func includePath(m *ast.MappingNode) (string, bool) {
	for _, mv := range m.Values {
		// Key.String() is fine — scalar key with no trailing comment in
		// practice. Value goes through GetToken() so any inline comment
		// (`include: foo.yml # note`) doesn't bleed into the path.
		if mv.Key.String() == "include" {
			return mv.Value.GetToken().Value, true
		}
	}

	return "", false
}

// Save writes every loaded file back to disk. The AST under each file's
// RootNode is the source of truth — existing items keep their exact
// on-disk form (comments, formatting, ordering) because nothing rewrites
// them. Only newly-added secrets (those with no origin AST node) and
// queued NewIncludes are appended via SequenceNode.Merge. Files with a
// nil RootNode (created in-memory by AddSecretDir for a directory that
// didn't have a sesam.yml yet) are written fresh.
func (c *ConfigRepository) Save() error {
	newOwned := map[*FileSource][]Secret{}
	for _, s := range c.MainFile.Config.Secrets {
		if s.Source == nil {
			return fmt.Errorf("secret %q has no Source; call Resolve before Save", s.Path)
		}

		if s.node == nil {
			newOwned[s.Source] = append(newOwned[s.Source], s)
		}
	}

	for _, src := range c.SourceFiles {
		if err := writeFile(src, newOwned[src]); err != nil {
			return err
		}
	}

	return nil
}

func writeFile(src *FileSource, newSecrets []Secret) error {
	if src.RootNode == nil {
		return writeFreshFile(src, newSecrets)
	}

	if len(newSecrets) > 0 || len(src.NewIncludes) > 0 {
		newSeq, err := buildNewItems(newSecrets, src.NewIncludes)
		if err != nil {
			return fmt.Errorf("%s: building new items: %w", src.Path, err)
		}

		existingSeq, err := secretsNode(src.RootNode)
		if err != nil {
			return fmt.Errorf("%s: %w", src.Path, err)
		}

		// SequenceNode.Merge aligns the new subtree's columns to the
		// existing sequence's indentation and appends its values.
		existingSeq.Merge(newSeq)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf, yaml.WithComment(src.CommentMap), yaml.IndentSequence(true))
	if err := enc.Encode(src.RootNode); err != nil {
		return fmt.Errorf("%s: encoding: %w", src.Path, err)
	}

	return os.WriteFile(src.Path, buf.Bytes(), 0o644)
}

// writeFreshFile emits a brand-new sesam.yml for a FileSource that was
// created in-memory (RootNode == nil). The owned secrets and any queued
// includes are written under the standard config: / secrets: shape.
func writeFreshFile(src *FileSource, owned []Secret) error {
	items := make([]Secret, 0, len(owned)+len(src.NewIncludes))
	items = append(items, owned...)
	for _, inc := range src.NewIncludes {
		items = append(items, Secret{Include: inc})
	}

	cfg := Config{Secrets: items}
	bs, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("%s: encoding: %w", src.Path, err)
	}

	// TODO: use renameio to write files atomically
	return os.WriteFile(src.Path, bs, 0o644)
}

// buildNewItems marshals `secrets` + `includes` as a YAML sequence and
// reparses to recover an *ast.SequenceNode suitable for SequenceNode.Merge.
func buildNewItems(secrets []Secret, includes []string) (*ast.SequenceNode, error) {
	items := make([]Secret, 0, len(secrets)+len(includes))
	items = append(items, secrets...)
	for _, inc := range includes {
		items = append(items, Secret{Include: inc})
	}

	bs, err := yaml.Marshal(items)
	if err != nil {
		return nil, err
	}

	file, err := parser.ParseBytes(bs, 0)
	if err != nil {
		return nil, err
	}

	if len(file.Docs) == 0 {
		return nil, fmt.Errorf("empty marshal output")
	}

	seq, ok := file.Docs[0].Body.(*ast.SequenceNode)
	if !ok {
		return nil, fmt.Errorf("expected sequence, got %T", file.Docs[0].Body)
	}

	return seq, nil
}
