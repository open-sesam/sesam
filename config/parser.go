package config

import (
	"fmt"

	"github.com/goccy/go-yaml"
)

type Config struct {
	General General `yaml:"general"`
	Secrets Secrets `yaml:"secrets"`
}

type General struct {
	EncryptAll bool `yaml:"encrypt_all"`
}

type Secrets struct {
	SecretType string `yaml:"type"`
	Path       string `yaml:"path"`
}

func Parse(data []byte) (*Config, error) {
	conf := &Config{}
	if err := yaml.Unmarshal(data, conf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml conf: %w", err)
	}

	return conf, nil
}
