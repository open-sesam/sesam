package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
)

// TODO: maybe this can somehow be done with a generic or sth,
// since a lot of functions are kinda duplicated.

type ConfigRepository struct {
	MainFile    *MainSource
	SecretFiles map[string]*SecretSource
}

func (c *ConfigRepository) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	cm := yaml.CommentMap{}
	decoder := yaml.NewDecoder(f, yaml.CommentToMap(cm))

	var root ast.Node

	if err := decoder.Decode(&root); err != nil {
		return err
	}

	cfg := &SesamConf{}

	if err := yaml.NodeToValue(root, cfg); err != nil {
		return err
	}

	c.MainFile = &MainSource{
		Path:       path,
		RootNode:   root,
		Config:     cfg,
		CommentMap: cm,
	}

	return nil
}

func loadYamlSubFile(path string) (*SecretSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cm := yaml.CommentMap{}
	decoder := yaml.NewDecoder(f, yaml.CommentToMap(cm))

	var root ast.Node

	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}

	cfg := &SubConf{}

	if err := yaml.NodeToValue(root, cfg); err != nil {
		return nil, err
	}

	file := &SecretSource{
		Path:       path,
		RootNode:   root,
		Secrets:    cfg,
		CommentMap: cm,
	}

	return file, nil
}

func saveMainFile(file *MainSource) error {
	var buf bytes.Buffer

	encoder := yaml.NewEncoder(&buf, yaml.WithComment(file.CommentMap))

	if err := encoder.Encode(file.RootNode); err != nil {
		return err
	}

	return os.WriteFile("new"+file.Path, buf.Bytes(), 0o644)
}

// TODO: this needs to work for both type of files
func (c *ConfigRepository) Save() error {
	var buf bytes.Buffer

	encoder := yaml.NewEncoder(&buf, yaml.WithComment(file.CommentMap))

	if err := encoder.Encode(file.RootNode); err != nil {
		return err
	}

	return os.WriteFile("new"+file.Path, buf.Bytes(), 0o644)
}

func (c *ConfigRepository) Resolve() error {
	file := c.MainFile
	fmt.Println("resolving includes from: ", file.Path)
	cfg := file.Config

	mapping := file.RootNode.(*ast.MappingNode)

	for _, value := range mapping.Values {
		keyNode := value.Key
		if keyNode.String() != "secrets" {
			continue
		}

		seq := value.Value.(*ast.SequenceNode)
		for _, item := range seq.Values {
			mapNode, ok := item.(*ast.MappingNode)
			if !ok {
				continue
			}

			for _, mv := range mapNode.Values {
				if mv.Key.String() == "include" {
					includePath := mv.Value.String()
					fullPath := filepath.Join(
						filepath.Dir(file.Path),
						includePath,
					)

					subFile, err := loadYamlSubFile(fullPath)
					if err != nil {
						return err
					}
					c.SecretFiles[fullPath] = subFile

					if err := c.resolveIncludesFromSub(subFile); err != nil {
						return err
					}

					cfg.Secrets = append(cfg.Secrets, subFile.Secrets.Secrets...)
				}
			}
		}
	}

	return nil
}

func (c *ConfigRepository) resolveIncludesFromSub(file *SecretSource) error {
	fmt.Println("resolving includes from: ", file.Path)
	cfg := file.Secrets

	mapping := file.RootNode.(*ast.MappingNode)

	for _, value := range mapping.Values {
		keyNode := value.Key
		if keyNode.String() != "secrets" {
			continue
		}

		seq := value.Value.(*ast.SequenceNode)
		for _, item := range seq.Values {
			mapNode, ok := item.(*ast.MappingNode)
			if !ok {
				continue
			}

			for _, mv := range mapNode.Values {
				if mv.Key.String() == "include" {
					includePath := mv.Value.String()
					fullPath := filepath.Join(
						filepath.Dir(file.Path),
						includePath,
					)

					subFile, err := loadYamlSubFile(fullPath)
					if err != nil {
						return err
					}
					c.SecretFiles[fullPath] = subFile

					if err := c.resolveIncludesFromSub(subFile); err != nil {
						return err
					}

					cfg.Secrets = append(cfg.Secrets, subFile.Secrets.Secrets...)
				}
			}
		}
	}

	return nil
}
