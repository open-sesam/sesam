package config

import (
	"fmt"
	"slices"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
)

func (c *Config) UserAddRecipient(user string, pubKeySpecs []string) error {
	src := c.MainFile
	seq, err := usersNode(src.RootNode)
	if err != nil {
		return err
	}

	for i, item := range seq.Values {
		userNode, ok := item.(*ast.MappingNode)
		if !ok {
			return fmt.Errorf("%s: users[%d] is not a mapping (got %T)", src.Path, i, item)
		}

		// Only operate on the requested user.
		if nv := findMappingValue(userNode, "name"); nv == nil || nv.Value.String() != user {
			continue
		}

		keyNode := findMappingValue(userNode, "key")
		if keyNode == nil {
			continue
		}

		keySeq, ok := keyNode.Value.(*ast.SequenceNode)
		if !ok {
			return fmt.Errorf("%s: user %q key is not a sequence (got %T)", src.Path, user, keyNode.Value)
		}

		newKeys, err := marshalSeq(pubKeySpecs)
		if err != nil {
			return err
		}

		keySeq.Merge(newKeys)
		return nil
	}

	return fmt.Errorf("%s: user %q not found", src.Path, user)
}

func (c *Config) UserRmRecipient(user string, pubKeySpecs []string) error {
	src := c.MainFile
	seq, err := usersNode(src.RootNode)
	if err != nil {
		return err
	}

	for i, item := range seq.Values {
		userNode, ok := item.(*ast.MappingNode)
		if !ok {
			return fmt.Errorf("%s: users[%d] is not a mapping (got %T)", src.Path, i, item)
		}

		// Only operate on the requested user.
		if nv := findMappingValue(userNode, "name"); nv == nil || nv.Value.String() != user {
			continue
		}

		keyNode := findMappingValue(userNode, "key")
		if keyNode == nil {
			continue
		}

		keySeq, ok := keyNode.Value.(*ast.SequenceNode)
		if !ok {
			return fmt.Errorf("%s: user %q key is not a sequence (got %T)", src.Path, user, keyNode.Value)
		}

		var existingKeys []string
		if err := yaml.NodeToValue(keySeq, &existingKeys); err != nil {
			return fmt.Errorf("%s: decode keys of user %q: %w", src.Path, user, err)
		}

		filteredKeys := slices.DeleteFunc(existingKeys, func(key string) bool {
			return slices.Contains(pubKeySpecs, key)
		})

		if len(filteredKeys) == 0 {
			return fmt.Errorf("%s: user %q must keep at least one key", src.Path, user)
		}

		filteredKeysNode, err := marshalSeq(filteredKeys)
		if err != nil {
			return err
		}

		keySeq.Values = filteredKeysNode.Values
		return nil
	}

	return fmt.Errorf("%s: user %q not found", src.Path, user)
}
