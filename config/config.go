package config

import (
	"fmt"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
)

// SesamConf struct repesents the whole sesam config
type SesamConf struct {
	Config  Config   `yaml:"config"`
	Secrets []Secret `yaml:"secrets"`
}

type MainSource struct {
	Path string

	RootNode   ast.Node
	CommentMap yaml.CommentMap

	Config *SesamConf
}

// Config struct repesents the main config part
type Config struct {
	General General `yaml:"general"`
	Users   []User  `yaml:"users"`
	Groups  Group   `yaml:"groups"`
}

type Group struct {
	Members []string
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
	Pub         string `yaml:"key"`
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
	case SSHKey:
	case Password:
	case Template:
	case Custom:
		return nil
	default:
	}

	return fmt.Errorf("unknown secret type: %s (valid options: ssh_key,password,template,custom)", v)
}

// Secret struct represents a single secret.
type Secret struct {
	SecretType  SecretType `yaml:"type,omitempty"`
	Name        string     `yaml:"name,omitempty"`
	Path        string     `yaml:"path,omitempty"`
	Access      []string   `yaml:"access,omitempty"`
	Description string     `yaml:"description,omitempty"`
	Rotate      []any      `yaml:"rotate,omitempty"`
	Swap        []Swap     `yaml:"swap,omitempty"` // TODO: add optional where it applies

	Source *SecretSource `yaml:"-"`
}

// Swap struct repesents the swap config of a secret. Multiple commands can be defined here
type Swap struct {
	Cmd string `yaml:"cmd"`
}

type SubConf struct {
	Secrets []Secret `yaml:"secrets"`
}

type SecretSource struct {
	Path string

	RootNode   ast.Node
	CommentMap yaml.CommentMap

	Secrets *SubConf
}
