package config

import (
	"github.com/goccy/go-yaml/ast"
)

// FileSource carries the parsed AST for one on-disk YAML file. Every file the
// repository touches — the entry file and each transitively-included one —
// gets exactly one FileSource.
//
// RootNode is the single source of truth. The file is parsed with
// parser.ParseComments, so comments live on the nodes themselves: inserting a
// node carries its comment in, cutting a node carries its comment out, and
// Save re-renders the tree verbatim via RootNode.String(). RootNode is nil
// only for a file created in memory that has not had its first item added yet;
// the first insert builds the root, and Save skips any source still nil.
type FileSource struct {
	Path     string
	RootNode ast.Node
}

/////////////////
// USER CONFIG //
/////////////////

// User is a data view of a single entry in the main file's users: sequence. It
// is decoded from / marshaled to the AST on demand; the AST stays
// authoritative.
type User struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"desc,omitempty"`
	Key         []string `yaml:"key,omitempty"`
}

///////////////////
// SECRET CONFIG //
///////////////////

// Secret is a data view of one entry in a secrets: sequence. When Include is
// set (and the other fields are zero) the value represents an
// `- include: <path>` placeholder rather than a real secret. Like User it is a
// view over the AST, used both to decode existing entries and to marshal new
// nodes before they are inserted.
type Secret struct {
	Include     string   `yaml:"include,omitempty"`
	Name        string   `yaml:"name,omitempty"`
	Path        string   `yaml:"path,omitempty"`
	Access      []string `yaml:"access,omitempty"`
	Description string   `yaml:"desc,omitempty"`
	Rotate      []any    `yaml:"rotate,omitempty"`
	Swap        []Swap   `yaml:"swap,omitempty"`
}

// Swap struct repesents the swap config of a secret. Multiple commands can be defined here
type Swap struct {
	Cmd string `yaml:"cmd"`
}
