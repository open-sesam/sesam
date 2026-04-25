package config

import "time"

// SesamConf struct repesents the whole sesam config
type SesamConf struct {
	Version int      `yaml:"version"`
	Verify  Verify   `yaml:"verify"`
	Config  Config   `yaml:"config"`
	Secrets []Secret `yaml:"secrets"`
}

// Config struct repesents the main config part
type Config struct {
	General General          `yaml:"general"`
	Users   []User           `yaml:"users"`
	Groups  []map[string]any `yaml:"groups"` // TODO: maybe groups should be mapped?
}

type Verify struct {
	Hash         string    `yaml:"hash"`
	SignedBy     string    `yaml:"signed_by"`
	Signature    string    `yaml:"signature"`
	LastModified time.Time `yaml:"last_modified"`
	ModifiedBy   string    `yaml:"modified_by"`
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
	Description string `yaml:"desc"`
	Key         string `yaml:"key"`
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

// Secret struct represents a single secret.
type Secret struct {
	SecretType  SecretType `yaml:"type"`
	Name        string     `yaml:"name"`
	Path        string     `yaml:"path"`
	Access      []string   `yaml:"access"`
	Description string     `yaml:"description"`
	Rotate      []any      `yaml:"rotate"`
	Swap        []Swap     `yaml:"swap,omitempty"` // TODO: add optional where it applies
}

// Swap struct repesents the swap config of a secret. Multiple commands can be defined here
type Swap struct {
	Cmd string `yaml:"cmd"`
}
