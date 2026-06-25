package config

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/google/renameio/v2"
	"github.com/open-sesam/sesam/core"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed sesam_schema.json
var schemaFS embed.FS

const schemaFile = "sesam_schema.json"

// Config holds every loaded file. MainFile is the top level file
// passed to Load; it is also present in SourceFiles (keyed by path) so Save can
// iterate one map and treat every file uniformly.
//
// There is no merged secrets list stored anywhere: the AST under each file's
// RootNode is the source of truth, and the flattened view is derived on demand
// (Secrets) by walking it.
type Config struct {
	MainFile    *FileSource
	SourceFiles map[string]*FileSource
	JSONSchema  *jsonschema.Schema

	// root confines all config file I/O to the repository. Every FileSource
	// path is relative to it.
	root *os.Root
}

// secretEntry is a transient view of one real (non-include) secret, pairing its
// decoded data with the AST node and the file it came from. It is recomputed
// from the AST on demand and never stored.
type secretEntry struct {
	source *FileSource
	node   *ast.MappingNode
	secret Secret
}

// Load is the entry function for ConfigRepository. The main sesam.yml file
// should be passed to Load as a repo-relative path. It parses the file and
// every transitively-included file into the AST, validating each against the
// JSON schema as it goes.
//
// All FileSource paths — MainFile.Path and every path derived from it — are
// kept relative to root, which is also the coordinate the revealed paths the
// single-secret mutators (SecretAdd/SecretRemove/SecretMove) match against.
func Load(root *os.Root, path string) (*Config, error) {
	path = filepath.Clean(path)

	// Load the JSON schema from the embedded FS so every file can be validated
	// later (on load and before save).
	configRepo := &Config{
		SourceFiles: map[string]*FileSource{},
		root:        root,
	}

	sch, err := compileSchema()
	if err != nil {
		return nil, fmt.Errorf("failed to compile json schema: %w", err)
	}
	configRepo.JSONSchema = sch

	src, err := configRepo.loadTree(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config tree: %w", err)
	}
	configRepo.MainFile = src

	// Walk the merged secrets once now so structural errors (a non-mapping
	// secrets item, a dangling include) surface at load time rather than on the
	// first read.
	if _, err := configRepo.secretEntries(); err != nil {
		return nil, fmt.Errorf("config structure seems off: %w", err)
	}

	return configRepo, nil
}

var (
	schemaOnce   sync.Once
	cachedSchema *jsonschema.Schema
	errSchema    error
)

// compileSchema returns the compiled sesam JSON schema. The embedded schema is
// immutable and the compiled *jsonschema.Schema is read-only (used only for
// Validate, which is safe for concurrent use), so it is compiled once per
// process and shared across all Config instances.
func compileSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		cachedSchema, errSchema = compileSchemaUncached()
	})
	return cachedSchema, errSchema
}

// compileSchemaUncached reads and compiles the embedded sesam JSON schema.
func compileSchemaUncached() (*jsonschema.Schema, error) {
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
func (c *Config) validate(v any, path string) error {
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

// loadFile parses one file into the AST (comments attached to nodes) and
// validates it against the schema. It does not follow includes.
func (c *Config) loadFile(path string) (*FileSource, error) {
	bs, err := c.root.ReadFile(path)
	if err != nil {
		return nil, err
	}

	file, err := parser.ParseBytes(bs, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	if len(file.Docs) == 0 || file.Docs[0].Body == nil {
		return nil, fmt.Errorf("%s: empty YAML document", path)
	}

	// Validate against the schema by decoding the raw bytes into a generic
	// value, so every key on disk (including ones no struct models) is checked.
	var doc any
	if err := yaml.Unmarshal(bs, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.validate(doc, path); err != nil {
		return nil, err
	}

	return &FileSource{Path: path, RootNode: file.Docs[0].Body}, nil
}

// loadTree loads path (unless already loaded) and recurses into every include
// it declares, registering each file in SourceFiles.
func (c *Config) loadTree(path string) (*FileSource, error) {
	if existing, ok := c.SourceFiles[path]; ok {
		return existing, nil
	}

	src, err := c.loadFile(path)
	if err != nil {
		return nil, err
	}
	c.SourceFiles[path] = src

	for _, inc := range fileIncludes(src.RootNode) {
		p := filepath.Join(filepath.Dir(path), inc)
		if _, err := c.loadTree(p); err != nil {
			return nil, fmt.Errorf("loading include %s: %w", p, err)
		}
	}

	return src, nil
}

// secretEntries walks the main file and every included file, returning one
// entry per real secret in include order. The list is derived fresh from the
// AST every call.
func (c *Config) secretEntries() ([]secretEntry, error) {
	return c.collectSecrets(c.MainFile, map[string]bool{})
}

// collectSecrets returns the real secrets in src, splicing in the secrets of
// any included file at the point the include appears. visiting holds the files
// on the current include chain so a cycle (a file that transitively includes
// itself) is detected and rejected instead of recursing forever.
func (c *Config) collectSecrets(src *FileSource, visiting map[string]bool) ([]secretEntry, error) {
	if visiting[src.Path] {
		return nil, fmt.Errorf("include loop detected at %s", src.Path)
	}
	visiting[src.Path] = true
	defer delete(visiting, src.Path)

	seq, err := secretsNode(src.RootNode)
	if err != nil {
		return nil, errors.New("missing secrets: key")
	}

	var out []secretEntry
	for i, item := range seq.Values {
		mapNode, ok := item.(*ast.MappingNode)
		if !ok {
			return nil, fmt.Errorf("%s: secrets[%d] is not a mapping (got %T)", src.Path, i, item)
		}

		if inc, ok := includePath(mapNode); ok {
			p := filepath.Join(filepath.Dir(src.Path), inc)
			sub, ok := c.SourceFiles[p]
			if !ok {
				return nil, fmt.Errorf("%s: include %s is not loaded", src.Path, inc)
			}

			subEntries, err := c.collectSecrets(sub, visiting)
			if err != nil {
				return nil, err
			}
			out = append(out, subEntries...)
			continue
		}

		var s Secret
		if err := yaml.NodeToValue(mapNode, &s); err != nil {
			return nil, fmt.Errorf("%s: decoding secrets[%d]: %w", src.Path, i, err)
		}

		out = append(out, secretEntry{source: src, node: mapNode, secret: s})
	}

	return out, nil
}

// TODO: could use some optimization, as it's executed for every SecretAdd call. If adding
// multiple secrets at once (or large directories), it's probably easier to compute once and
// update when addSecret is called.
//
// trackedRevealedPaths returns the set of absolute on-disk paths of every real
// secret declared across all loaded files. It walks each file's own secrets
// directly (not via includes) so it is independent of include reachability —
// covering sub-files that are mid-creation and not yet wired up — which makes
// it the basis for both global dedup and reporting which secrets a mutation
// added. The same physical file tracked by two files collapses to one entry,
// which is exactly the duplicate we refuse to create.
func (c *Config) trackedRevealedPaths() map[string]bool {
	set := map[string]bool{}
	for _, src := range c.SourceFiles {
		for _, s := range ownSecrets(src) {
			set[filepath.Join(filepath.Dir(src.Path), s.Path)] = true
		}
	}
	return set
}

// Secrets returns the merged, flattened secrets across the main file and all
// included files, in include order, decoded fresh from the AST.
func (c *Config) Secrets() ([]Secret, error) {
	entries, err := c.secretEntries()
	if err != nil {
		return nil, err
	}

	out := make([]Secret, len(entries))
	for i, e := range entries {
		out[i] = e.secret
	}
	return out, nil
}

// Users returns the users declared in the main file, decoded from its AST. A
// main file without a users: key yields an empty slice.
func (c *Config) Users() ([]User, error) {
	seq, err := usersNode(c.MainFile.RootNode)
	if err != nil {
		return nil, nil //nolint:nilerr // absent users: key means no users
	}

	users := make([]User, 0, len(seq.Values))
	for i, item := range seq.Values {
		mapNode, ok := item.(*ast.MappingNode)
		if !ok {
			return nil, fmt.Errorf("%s: users[%d] is not a mapping (got %T)", c.MainFile.Path, i, item)
		}

		var u User
		if err := yaml.NodeToValue(mapNode, &u); err != nil {
			return nil, fmt.Errorf("%s: decoding users[%d]: %w", c.MainFile.Path, i, err)
		}
		users = append(users, u)
	}

	return users, nil
}

// Groups returns the group→members mapping from the main file. A main file
// without a groups: key yields an empty map.
func (c *Config) Groups() (map[string][]string, error) {
	m, err := groupsNode(c.MainFile.RootNode)
	if err != nil {
		// Absent groups: key means no groups.
		return map[string][]string{}, nil //nolint:nilerr // absent groups: key is not an error
	}

	var groups map[string][]string
	if err := yaml.NodeToValue(m, &groups); err != nil {
		return nil, fmt.Errorf("%s: decoding groups: %w", c.MainFile.Path, err)
	}
	return groups, nil
}

// Save writes every loaded file back to disk. Each file's RootNode already
// reflects every edit — nodes were inserted or cut in place — so Save just
// re-renders the AST (comments and original formatting included) and validates
// it before writing.
func (c *Config) Save() error {
	// writeFile stages temps in .sesam/tmp; ensure it exists. In a real repo
	// ensureSesamDirs already created it, so this is a no-op there.
	if err := c.root.MkdirAll(core.SesamTmpDir(), 0o700); err != nil {
		return fmt.Errorf("create scratch dir: %w", err)
	}

	for _, src := range c.SourceFiles {
		if err := c.writeFile(src); err != nil {
			return err
		}
	}

	return nil
}

// writeFile renders src's AST to YAML and validates the result against the JSON
// schema before writing. RootNode.String() preserves the node-attached
// comments and original formatting that yaml.Encoder would otherwise drop. A
// source whose RootNode is still nil (created in memory but never given an
// item) has nothing to persist and is skipped.
func (c *Config) writeFile(src *FileSource) error {
	if src.RootNode == nil {
		return nil
	}

	out := src.RootNode.String()
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}

	// Validate the document we are about to write by decoding it back into a
	// generic value the JSON schema can check.
	var doc any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		return fmt.Errorf("%s: decoding for validation: %w", src.Path, err)
	}
	if err := c.validate(doc, src.Path); err != nil {
		return err
	}

	// fmt.Printf("SAVING FILE:\n%s\n", string(out))
	// Stage the temp in .sesam/tmp (same as the rest of sesam) so it never
	// lands in the worktree; Save ensures the directory exists.
	return renameio.WriteFile(src.Path, []byte(out), 0o644,
		renameio.WithRoot(c.root), renameio.WithTempDir(core.SesamTmpDir()))
}

////////////////////
// AST NAVIGATION //
////////////////////

// fileIncludes returns the include paths declared in a file's secrets sequence.
func fileIncludes(root ast.Node) []string {
	seq, err := secretsNode(root)
	if err != nil {
		return nil
	}

	var paths []string
	for _, item := range seq.Values {
		m, ok := item.(*ast.MappingNode)
		if !ok {
			continue
		}
		if inc, ok := includePath(m); ok {
			paths = append(paths, inc)
		}
	}
	return paths
}

// ownSecrets returns the real (non-include) secrets declared directly in src,
// without descending into includes.
func ownSecrets(src *FileSource) []Secret {
	seq, err := secretsNode(src.RootNode)
	if err != nil {
		return nil
	}

	var out []Secret
	for _, item := range seq.Values {
		m, ok := item.(*ast.MappingNode)
		if !ok {
			continue
		}
		if _, isInc := includePath(m); isInc {
			continue
		}

		var s Secret
		if yaml.NodeToValue(m, &s) == nil {
			out = append(out, s)
		}
	}
	return out
}

func usersNode(root ast.Node) (*ast.SequenceNode, error) {
	mv, err := findRootValue(root, "users")
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

// secretsNode returns the *ast.SequenceNode at the root's secrets: key, or an
// error if the structure doesn't match.
func secretsNode(root ast.Node) (*ast.SequenceNode, error) {
	mv, err := findRootValue(root, "secrets")
	if err != nil {
		return nil, err
	}

	seq, ok := mv.Value.(*ast.SequenceNode)
	if !ok {
		return nil, fmt.Errorf("expected sequence under secrets, got %T", mv.Value)
	}

	return seq, nil
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

// removeMappingValue deletes the key/value pair for `key` from m, returning
// true if it was present.
func removeMappingValue(m *ast.MappingNode, key string) bool {
	for i, mv := range m.Values {
		if mv.Key.String() == key {
			m.Values = append(m.Values[:i], m.Values[i+1:]...)
			return true
		}
	}

	return false
}

// findRootValue returns the top-level MappingValueNode whose key matches, or an
// error if absent. A file whose only top-level key is e.g. `secrets:` (a
// typical sub-file) can parse to a single *ast.MappingValueNode rather than an
// *ast.MappingNode, so both shapes are handled.
func findRootValue(root ast.Node, key string) (*ast.MappingValueNode, error) {
	for _, mv := range rootMappingValues(root) {
		if mv.Key.String() == key {
			return mv, nil
		}
	}

	return nil, fmt.Errorf("no %s: key in root", key)
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

//////////////////
// AST MUTATION //
//////////////////

// appendSecretsItems appends the given secret/include items to src's secrets
// sequence. It creates the file's root and/or its secrets: key when missing, so
// it works uniformly for an existing file and a brand-new in-memory one.
func appendSecretsItems(src *FileSource, items []Secret) error {
	if len(items) == 0 {
		return nil
	}

	// A brand-new file: build the whole document from the items.
	if src.RootNode == nil {
		root, err := marshalBody(map[string][]Secret{"secrets": items})
		if err != nil {
			return err
		}
		src.RootNode = root
		return nil
	}

	seq, err := secretsNode(src.RootNode)
	if err != nil {
		// Root exists but has no usable secrets: sequence — add the key.
		return appendRootKey(src, map[string][]Secret{"secrets": items})
	}

	newSeq, err := marshalSeq(items)
	if err != nil {
		return err
	}

	// SequenceNode.Merge aligns the new subtree's columns to the existing
	// sequence's indentation and appends its values.
	seq.Merge(newSeq)
	return nil
}

// appendRootKey adds the top-level key(s) in v to src's root mapping, aligning
// columns via MappingNode.Merge. A single-key root (*ast.MappingValueNode) is
// normalized to a mapping first. Used to create a secrets:/users:/groups:
// section that did not exist on disk.
func appendRootKey(src *FileSource, v any) error {
	rootMN, ok := src.RootNode.(*ast.MappingNode)
	if !ok {
		mv, ok := src.RootNode.(*ast.MappingValueNode)
		if !ok {
			return fmt.Errorf("%s: root is not a mapping (got %T)", src.Path, src.RootNode)
		}
		rootMN = ast.Mapping(mv.GetToken(), false, mv)
		src.RootNode = rootMN
	}

	mn, err := marshalMapping(v)
	if err != nil {
		return err
	}

	rootMN.Merge(mn)
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

// removeSeqValue removes Values[i] from seq together with the head comment that
// belongs to it. goccy attaches the first item's head comment to the sequence
// node itself (not to ValueHeadComments[0]); every other item's head comment
// lives in ValueHeadComments[i]. Handling index 0 specially keeps a removed
// item's comment from being inherited by whichever item shifts into its slot.
func removeSeqValue(seq *ast.SequenceNode, i int) {
	if i < 0 || i >= len(seq.Values) {
		return
	}

	seq.Values = slices.Delete(seq.Values, i, i+1)

	vhc := seq.ValueHeadComments
	if i == 0 {
		// The new first item's head comment (old index 1) must move onto the
		// sequence; the removed item's comment lived there and is dropped.
		var promoted *ast.CommentGroupNode
		if len(vhc) > 1 {
			promoted = vhc[1]
		}
		seq.Comment = promoted

		if len(vhc) > 0 {
			seq.ValueHeadComments = slices.Delete(vhc, 0, 1)
		}
		if len(seq.ValueHeadComments) > 0 {
			// Its comment now lives on seq.Comment; clear the slot so it is not
			// rendered twice.
			seq.ValueHeadComments[0] = nil
		}
		return
	}

	if i < len(vhc) {
		seq.ValueHeadComments = slices.Delete(vhc, i, i+1)
	}
}

///////////////////
// AST MARSHALING //
///////////////////

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

// marshalBody marshals v to YAML and reparses it into an AST node.
func marshalBody(v any) (ast.Node, error) {
	bs, err := yaml.MarshalWithOptions(v, yaml.IndentSequence(true))
	if err != nil {
		return nil, err
	}

	file, err := parser.ParseBytes(bs, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	if len(file.Docs) == 0 {
		return nil, fmt.Errorf("empty marshal output")
	}

	return file.Docs[0].Body, nil
}
