package config

import (
	"fmt"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
)

// Config holds the top-level keys of a sesam YAML file. Every file — the
// entry file and each transitively-included one — shares this shape: there
// is no `config:` wrapper. Sub-files typically carry only `secrets:` and
// leave general/users/groups zero, which is why every field is optional.
type Config struct {
	General General             `yaml:"general,omitempty"`
	Users   []User              `yaml:"users,omitempty"`
	Groups  map[string][]string `yaml:"groups,omitempty"`
	Secrets []Secret            `yaml:"secrets,omitempty"`
}

// FileSource carries the parsed AST plus the decoded config for one on-disk
// YAML file. Every file the repository touches — the entry file and each
// transitively-included one — gets exactly one FileSource.
//
// The AST under RootNode is the source of truth for everything that
// originated on disk. Save re-encodes it untouched, preserving every
// original byte, comment, and formatting choice for items the API hasn't
// edited. RootNode is nil for files that don't exist on disk yet; Save
// writes those fresh from the in-memory state.
type FileSource struct {
	Path       string
	RootNode   ast.Node
	CommentMap yaml.CommentMap
	Config     *Config

	// NewIncludes are include paths the API has queued; Save appends them
	// to the existing secrets sequence (or, for new files, emits them as
	// part of the fresh content). Existing includes live in RootNode and
	// aren't tracked here.
	NewIncludes []string
}

////////////////////
// GENERAL CONFIG //
////////////////////

// General struct repesents general configuration options
type General struct {
	EncryptAll bool `yaml:"encrypt_all"`
}

/////////////////
// USER CONFIG //
/////////////////

// User struct represents a single user. Multiple users can be defined
type User struct {
	Name        string `yaml:"name"`
	Description string `yaml:"desc,omitempty"`
	Pub         string `yaml:"pub,omitempty"`
}

///////////////////
// SECRET CONFIG //
///////////////////

// SecretType represents the different types of secrets
type SecretType string

const (
	SSHKey   = SecretType("ssh_key")
	Password = SecretType("password")
	Template = SecretType("template")
	Custom   = SecretType("custom")
)

// VerifySecretType verifies if the given string matches a valid secret type
func VerifySecretType(v string) error {
	secretType := SecretType(v)
	switch secretType {
	case SSHKey, Password, Template, Custom:
		return nil
	default:
	}

	return fmt.Errorf("unknown secret type: %s (valid options: ssh_key,password,template,custom)", v)
}

// Secret represents one entry in a sesam YAML's secrets: sequence. When
// Include is set (and the other fields are zero) the value represents an
// `- include: <path>` placeholder rather than a real secret — only used at
// marshal time for newly-added includes; the merged Secrets list holds
// only real secrets (Include == "").
type Secret struct {
	Include     string     `yaml:"include,omitempty"`
	SecretType  SecretType `yaml:"type,omitempty"`
	Name        string     `yaml:"name,omitempty"`
	Path        string     `yaml:"path,omitempty"`
	Access      []string   `yaml:"access,omitempty"`
	Description string     `yaml:"description,omitempty"`
	Rotate      []any      `yaml:"rotate,omitempty"`
	Swap        []Swap     `yaml:"swap,omitempty"`

	Source *FileSource      `yaml:"-" json:"-"`
	node   *ast.MappingNode `yaml:"-" json:"-"` // origin AST node; nil for items added via the API since load
}

// Swap struct repesents the swap config of a secret. Multiple commands can be defined here
type Swap struct {
	Cmd string `yaml:"cmd"`
}
