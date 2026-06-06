package config

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed sesam_schema.json
var schemaFS embed.FS

const schemaFile = "sesam_schema.json"

// ConfigRepository holds every loaded file plus the merged secrets view.
// MainFile is the top level file passed to Load; it is also present in
// SourceFiles (keyed by path) so Save can iterate one map and treat every
// file uniformly.
type ConfigRepository struct {
	MainFile    *FileSource
	SourceFiles map[string]*FileSource
	JSONSchema  *jsonschema.Schema
}

func NewConfigRepository() *ConfigRepository {
	return &ConfigRepository{
		SourceFiles: map[string]*FileSource{},
	}
}

// Load is the entry function for ConfigRepository. Main sesam.yml file
// should be passed to Load.
func (c *ConfigRepository) Load(path string) error {
	// Load the JSON schema from the embedded FS so every config struct can be
	// validated later (on load and before save).
	sch, err := compileSchema()
	if err != nil {
		return err
	}
	c.JSONSchema = sch

	src, err := c.loadFile(path)
	if err != nil {
		return err
	}

	c.MainFile = src
	c.SourceFiles[path] = src

	return c.resolve()
}

// compileSchema reads and compiles the embedded sesam JSON schema.
func compileSchema() (*jsonschema.Schema, error) {
	data, err := schemaFS.ReadFile(schemaFile)
	if err != nil {
		return nil, err
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	comp := jsonschema.NewCompiler()
	if err := comp.AddResource(schemaFile, doc); err != nil {
		return nil, err
	}

	return comp.Compile(schemaFile)
}

// validate marshals v to JSON and checks it against the loaded schema. path is
// only used to give a useful error message.
func (c *ConfigRepository) validate(v any, path string) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return err
	}

	if err := c.JSONSchema.Validate(inst); err != nil {
		return fmt.Errorf("failed to validate %s: %w", path, err)
	}

	return nil
}

func (c *ConfigRepository) loadFile(path string) (*FileSource, error) {
	root, cm, err := readYAMLFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	if err := yaml.NodeToValue(root, cfg); err != nil {
		return nil, err
	}

	// Validate every sesam.yml against the schema as it is loaded.
	if err := c.validate(cfg, path); err != nil {
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
func (c *ConfigRepository) resolve() error {
	flat, err := c.resolveSource(c.MainFile)
	if err != nil {
		return err
	}

	c.MainFile.Config.Secrets = flat

	return c.resolveUsers()
}

// resolveUsers re-decodes the main file's users sequence, attaching each
// user's origin AST node. Save uses the node to tell loaded users (node set)
// apart from ones added via the API (node nil), so only the new ones are
// appended. Users live only in the main file. A main file without a users:
// key is left untouched.
func (c *ConfigRepository) resolveUsers() error {
	seq, err := usersNode(c.MainFile.RootNode)
	if err != nil {
		return nil
	}

	users := make([]User, 0, len(seq.Values))
	for i, item := range seq.Values {
		mapNode, ok := item.(*ast.MappingNode)
		if !ok {
			return fmt.Errorf("%s: users[%d] is not a mapping (got %T)", c.MainFile.Path, i, item)
		}

		var u User
		if err := yaml.NodeToValue(mapNode, &u); err != nil {
			return fmt.Errorf("%s: decoding users[%d]: %w", c.MainFile.Path, i, err)
		}

		u.node = mapNode
		users = append(users, u)
	}

	c.MainFile.Config.Users = users
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
			sub, err := c.loadFile(path)
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

func usersNode(root ast.Node) (*ast.SequenceNode, error) {
	mv, err := findUsersValue(root)
	if err != nil {
		return nil, err
	}

	seq, ok := mv.Value.(*ast.SequenceNode)
	if !ok {
		return nil, fmt.Errorf("expected sequence under users, got %T", mv.Value)
	}

	return seq, nil
}

// groupsNode returns the *ast.MappingNode at the root's groups: key. goccy
// parses a groups: block as a mapping node even when it holds a single group.
func groupsNode(root ast.Node) (*ast.MappingNode, error) {
	mv, err := findRootValue(root, "groups")
	if err != nil {
		return nil, err
	}

	m, ok := mv.Value.(*ast.MappingNode)
	if !ok {
		return nil, fmt.Errorf("expected mapping under groups, got %T", mv.Value)
	}

	return m, nil
}

// findMappingValue returns the child key/value pair of m whose key matches, or
// nil when absent.
func findMappingValue(m *ast.MappingNode, key string) *ast.MappingValueNode {
	for _, mv := range m.Values {
		if mv.Key.String() == key {
			return mv
		}
	}

	return nil
}

// secretsNode returns the *ast.SequenceNode at the root's secrets: key, or
// an error if the structure doesn't match.
func secretsNode(root ast.Node) (*ast.SequenceNode, error) {
	mv, err := findSecretsValue(root)
	if err != nil {
		return nil, err
	}

	seq, ok := mv.Value.(*ast.SequenceNode)
	if !ok {
		return nil, fmt.Errorf("expected sequence under secrets, got %T", mv.Value)
	}

	return seq, nil
}

// findRootValue returns the top-level MappingValueNode whose key matches, or
// an error if absent. A file whose only top-level key is e.g. `secrets:` (a
// typical sub-file) parses to a single *ast.MappingValueNode rather than an
// *ast.MappingNode, so both shapes are handled.
func findRootValue(root ast.Node, key string) (*ast.MappingValueNode, error) {
	for _, mv := range rootMappingValues(root) {
		if mv.Key.String() == key {
			return mv, nil
		}
	}

	return nil, fmt.Errorf("no %s: key in root", key)
}

func findSecretsValue(root ast.Node) (*ast.MappingValueNode, error) {
	return findRootValue(root, "secrets")
}

func findUsersValue(root ast.Node) (*ast.MappingValueNode, error) {
	return findRootValue(root, "users")
}

// rootMappingValues returns the top-level key/value pairs of a YAML document
// root, normalizing the single-key case (*ast.MappingValueNode) and the
// multi-key case (*ast.MappingNode) into one slice. Returns nil for any other
// node type.
func rootMappingValues(root ast.Node) []*ast.MappingValueNode {
	switch n := root.(type) {
	case *ast.MappingNode:
		return n.Values
	case *ast.MappingValueNode:
		return []*ast.MappingValueNode{n}
	default:
		return nil
	}
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
// nil RootNode (created in-memory by AddSecrets for a directory that
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
		if err := c.writeFile(src, newOwned[src]); err != nil {
			return err
		}
	}

	return nil
}

// writeFile encodes src back to disk and validates the result against the
// JSON schema before writing. A file already on disk (RootNode != nil) has its
// new secrets/includes merged into the existing AST so comments, formatting
// and ordering survive untouched; a file created in-memory (RootNode == nil)
// is written fresh from a Config built out of its owned secrets and queued
// includes.
func (c *ConfigRepository) writeFile(src *FileSource, newSecrets []Secret) error {
	encOpts := []yaml.EncodeOption{yaml.IndentSequence(true)}

	var toEncode any
	if src.RootNode == nil {
		items := make([]Secret, 0, len(newSecrets)+len(src.NewIncludes))
		items = append(items, newSecrets...)
		for _, inc := range src.NewIncludes {
			items = append(items, Secret{Include: inc})
		}

		toEncode = Config{Secrets: items}
	} else {
		if len(newSecrets) > 0 || len(src.NewIncludes) > 0 {
			newSeq, err := buildNewSecretItems(newSecrets, src.NewIncludes)
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

		// Users and groups live only in the main file. Append any users added
		// since load and reconcile group memberships into its AST.
		if src == c.MainFile {
			if err := c.mergeNewUsers(src); err != nil {
				return err
			}

			if err := c.mergeGroups(src); err != nil {
				return err
			}
		}

		toEncode = src.RootNode
		encOpts = append(encOpts, yaml.WithComment(src.CommentMap))
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf, encOpts...)
	if err := enc.Encode(toEncode); err != nil {
		return fmt.Errorf("%s: encoding: %w", src.Path, err)
	}

	// Validate the document we are about to write. The encoder emits YAML, so
	// decode it back into a generic value the JSON schema can check.
	var doc any
	if err := yaml.Unmarshal(buf.Bytes(), &doc); err != nil {
		return fmt.Errorf("%s: decoding for validation: %w", src.Path, err)
	}

	if err := c.validate(doc, src.Path); err != nil {
		return err
	}

	return os.WriteFile(src.Path, buf.Bytes(), 0o644)
}

// buildNewSecretItems marshals `secrets` + `includes` as a YAML sequence and
// reparses to recover an *ast.SequenceNode suitable for SequenceNode.Merge.
func buildNewSecretItems(secrets []Secret, includes []string) (*ast.SequenceNode, error) {
	items := make([]Secret, 0, len(secrets)+len(includes))
	items = append(items, secrets...)
	for _, inc := range includes {
		items = append(items, Secret{Include: inc})
	}

	return marshalSeq(items)
}

// marshalSeq marshals v (a slice) to YAML and reparses it into an
// *ast.SequenceNode suitable for SequenceNode.Merge, which aligns the new
// subtree's columns to the target before appending.
func marshalSeq(v any) (*ast.SequenceNode, error) {
	body, err := marshalBody(v)
	if err != nil {
		return nil, err
	}

	seq, ok := body.(*ast.SequenceNode)
	if !ok {
		return nil, fmt.Errorf("expected sequence, got %T", body)
	}

	return seq, nil
}

// marshalMapping marshals v (a map) to YAML and reparses it into an
// *ast.MappingNode suitable for MappingNode.Merge.
func marshalMapping(v any) (*ast.MappingNode, error) {
	body, err := marshalBody(v)
	if err != nil {
		return nil, err
	}

	m, ok := body.(*ast.MappingNode)
	if !ok {
		return nil, fmt.Errorf("expected mapping, got %T", body)
	}

	return m, nil
}

func marshalBody(v any) (ast.Node, error) {
	bs, err := yaml.Marshal(v)
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

	return file.Docs[0].Body, nil
}

// mergeNewUsers appends users added since load (node nil) to the main file's
// users sequence, creating the users: key if it is missing.
func (c *ConfigRepository) mergeNewUsers(src *FileSource) error {
	var fresh []User
	for _, u := range c.MainFile.Config.Users {
		if u.node == nil {
			fresh = append(fresh, u)
		}
	}

	if len(fresh) == 0 {
		return nil
	}

	seq, err := usersNode(src.RootNode)
	if err != nil {
		// No users: key yet — add the whole sequence as a new top-level key.
		return appendRootKey(src.RootNode, map[string][]User{"users": fresh})
	}

	newSeq, err := marshalSeq(fresh)
	if err != nil {
		return fmt.Errorf("%s: building new users: %w", src.Path, err)
	}

	seq.Merge(newSeq)
	return nil
}

// mergeGroups reconciles in-memory group memberships into the main file's
// groups mapping: missing members are appended to existing groups and entirely
// new groups are added. Existing members are left untouched, so re-saving does
// not duplicate them. The groups: key is created if missing.
func (c *ConfigRepository) mergeGroups(src *FileSource) error {
	if len(c.MainFile.Config.Groups) == 0 {
		return nil
	}

	groups, err := groupsNode(src.RootNode)
	if err != nil {
		// No groups: key yet — add the whole mapping.
		return appendRootKey(src.RootNode, map[string]map[string][]string{"groups": c.MainFile.Config.Groups})
	}

	// Deterministic order so newly-added groups land predictably.
	names := make([]string, 0, len(c.MainFile.Config.Groups))
	for name := range c.MainFile.Config.Groups {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		members := c.MainFile.Config.Groups[name]

		mv := findMappingValue(groups, name)
		if mv == nil {
			newGroup, err := marshalMapping(map[string][]string{name: members})
			if err != nil {
				return fmt.Errorf("%s: building group %q: %w", src.Path, name, err)
			}

			groups.Merge(newGroup)
			continue
		}

		seq, ok := mv.Value.(*ast.SequenceNode)
		if !ok {
			return fmt.Errorf("%s: group %q is not a sequence (got %T)", src.Path, name, mv.Value)
		}

		if err := addMissingMembers(seq, members); err != nil {
			return fmt.Errorf("%s: group %q: %w", src.Path, name, err)
		}
	}

	return nil
}

// addMissingMembers appends to seq any member not already present.
func addMissingMembers(seq *ast.SequenceNode, members []string) error {
	present := make(map[string]bool, len(seq.Values))
	for _, v := range seq.Values {
		present[v.GetToken().Value] = true
	}

	var missing []string
	for _, m := range members {
		if !present[m] {
			missing = append(missing, m)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	newSeq, err := marshalSeq(missing)
	if err != nil {
		return err
	}

	seq.Merge(newSeq)
	return nil
}

// appendRootKey adds the top-level key(s) in v to a root mapping node, aligning
// columns via MappingNode.Merge. Used to create a users:/groups: section that
// did not exist on disk.
func appendRootKey(root ast.Node, v any) error {
	rootMN, ok := root.(*ast.MappingNode)
	if !ok {
		return fmt.Errorf("root is not a mapping (got %T)", root)
	}

	mn, err := marshalMapping(v)
	if err != nil {
		return err
	}

	rootMN.Merge(mn)
	return nil
}
