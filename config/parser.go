package config

import (
	"fmt"
	"io"
	"os"

	"github.com/goccy/go-yaml"
)

// ConfParser holds additional information about the
// config file like comments (TODO: find a way to preserve newlines)
type ConfParser struct {
	Decoder    *yaml.Decoder
	CommentMap map[string][]*yaml.Comment
}

func NewConfParser(reader io.Reader) *ConfParser {
	commentMap := map[string][]*yaml.Comment{}
	decoder := yaml.NewDecoder(reader, yaml.CommentToMap(commentMap))

	return &ConfParser{
		Decoder:    decoder,
		CommentMap: commentMap,
	}
}

// Parse parses the given file into the SesamConf struct
func (c *ConfParser) Parse() (*SesamConf, error) {
	conf := &SesamConf{}
	if err := c.Decoder.Decode(conf); err != nil {
		return nil, fmt.Errorf("failed to decode file: %w", err)
	}

	return conf, nil
}

func (c *ConfParser) Write(conf *SesamConf) error {
	b, err := yaml.MarshalWithOptions(conf, yaml.WithComment(c.CommentMap))
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile("/home/johnny/repos/sesam/mini-conf-parsed.yaml", b, 0o644)
}
