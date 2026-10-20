package config

import (
	"fmt"
	"slices"

	"github.com/goccy/go-yaml/ast"
)

func (c *Config) renameUserInGroups(oldName, newName string) error {
	src := c.MainFile
	if _, err := findRootValue(src.RootNode, "groups"); err != nil {
		return nil //nolint:nilerr // no groups: key, nothing to rename
	}

	seq, err := groupsNode(src.RootNode)
	if err != nil {
		return err
	}

	for _, item := range seq.Values {
		// Renaming inside a shared (anchored) list is right for every group using it.
		groupSeq, _ := resolveMemberSeq(src.RootNode, item.Value)
		if groupSeq == nil {
			return fmt.Errorf("%s: group %q value is not a sequence (got %T)", src.Path, item.Key.GetToken().Value, item.Value)
		}

		for i, userNode := range groupSeq.Values {
			if userNode.GetToken().Value == oldName {
				// Marshalled, so a name like `123` stays a quoted string.
				n, err := marshalBody(newName)
				if err != nil {
					return err
				}
				groupSeq.Values[i] = n
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

		// Only operate on the requested user. GetToken().Value (not String())
		// so an inline comment on the name does not defeat the match.
		if nv := findMappingValue(userNode, "name"); nv == nil || nv.Value.GetToken().Value != oldName {
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
		// No groups: key yet - every target group is new, so build the whole
		// mapping at once (mirrors addGroupMember's handling of the same gap
		// for a brand new user).
		newGroups := make(map[string][]string, len(groups))
		for _, group := range groups {
			newGroups[group] = []string{user}
		}
		return appendRootKey(src, map[string]map[string][]string{"groups": newGroups})
	}

	groupMap := make(map[string]bool, len(groups))
	for _, group := range groups {
		groupMap[group] = true
	}

	var emptyGroups []string // groups that are now empty

	for _, item := range seq.Values {
		groupName := item.Key.GetToken().Value
		groupSeq, shared := resolveMemberSeq(src.RootNode, item.Value)
		if groupSeq == nil {
			return fmt.Errorf("%s: group %q value is not a sequence (got %T)", src.Path, item.Key.GetToken().Value, item.Value)
		}

		userFound := slices.ContainsFunc(groupSeq.Values, func(n ast.Node) bool { return n.GetToken().Value == user })
		if shared && userFound != groupMap[groupName] {
			// The list is shared via an anchor; editing it would change the
			// other groups using it too.
			return fmt.Errorf(
				"%s: group %q shares its member list through an anchor; change %s's membership there by hand",
				src.Path, groupName, user,
			)
		}

		for idx, userNode := range groupSeq.Values {
			if userNode.GetToken().Value == user {
				if !groupMap[item.Key.GetToken().Value] {
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
		return slices.Contains(emptyGroups, mv.Key.GetToken().Value)
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
