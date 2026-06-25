package config

import (
	"fmt"
	"slices"

	"github.com/goccy/go-yaml/ast"
)

func (c *Config) renameUserInGroups(oldName, newName string) error {
	src := c.MainFile
	seq, err := groupsNode(src.RootNode)
	if err != nil {
		return err
	}

	for _, item := range seq.Values {
		groupSeq, ok := item.Value.(*ast.SequenceNode)
		if !ok {
			return fmt.Errorf("%s: group %q value is not a sequence (got %T)", src.Path, item.Key.String(), item.Value)
		}

		for _, userNode := range groupSeq.Values {
			if userNode.String() == oldName {
				s, ok := userNode.(*ast.StringNode)
				if !ok {
					return fmt.Errorf("%s: group %q member is not a string (got %T)", src.Path, item.Key.String(), userNode)
				}

				s.Value = newName
			}
		}
	}

	return nil
}

func (c *Config) UserRename(oldName, newName string) error {
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
		if nv := findMappingValue(userNode, "name"); nv == nil || nv.Value.String() != oldName {
			continue
		}

		nameNode := findMappingValue(userNode, "name")
		if nameNode == nil {
			continue
		}

		newNameNode, err := marshalBody(newName)
		if err != nil {
			return err
		}

		nameNode.Value = newNameNode

		return c.renameUserInGroups(oldName, newName)
	}

	return fmt.Errorf("%s: user %q not found", src.Path, oldName)
}

func (c *Config) UserChangeGroups(user string, groups []string) error {
	src := c.MainFile
	seq, err := groupsNode(src.RootNode)
	if err != nil {
		return err
	}

	groupMap := make(map[string]bool, len(groups))
	for _, group := range groups {
		groupMap[group] = true
	}

	var emptyGroups []string // groups that are now empty

	for _, item := range seq.Values {
		groupName := item.Key.String()
		groupSeq, ok := item.Value.(*ast.SequenceNode)
		if !ok {
			return fmt.Errorf("%s: group %q value is not a sequence (got %T)", src.Path, item.Key.String(), item.Value)
		}

		var userFound bool

		for idx, userNode := range groupSeq.Values {
			if userNode.String() == user {
				userFound = true
				if !groupMap[item.Key.String()] {
					// config says user is in this group, but should not be anymore.
					// we need to remove the node.
					removeSeqValue(groupSeq, idx)

					if len(groupSeq.Values) == 0 {
						emptyGroups = append(emptyGroups, groupName)
					}
				}

				break
			}
		}

		if !userFound {
			// config says user is not in this group, but should be.
			if groupMap[groupName] {

				userSingleSeq, err := marshalSeq([]string{user})
				if err != nil {
					return err
				}

				groupSeq.Merge(userSingleSeq)
			}
		}

		delete(groupMap, groupName)
	}

	// make sure empty groups are gone:
	seq.Values = slices.DeleteFunc(seq.Values, func(mv *ast.MappingValueNode) bool {
		return slices.Contains(emptyGroups, mv.Key.String())
	})

	// create the rest of the groups, if there were new ones.
	newGroups := make(map[string][]string)
	for newGroup := range groupMap {
		newGroups[newGroup] = []string{user}
	}

	if len(newGroups) > 0 {
		newGroupNode, err := marshalMapping(newGroups)
		if err != nil {
			return err
		}

		seq.Merge(newGroupNode)
	}

	return nil
}
