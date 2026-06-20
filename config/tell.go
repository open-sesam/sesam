package config

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
)

// Tell adds a new user to the main sesam.yml: a name, one or more keys and the
// groups the user should belong to. The user node is inserted into the main
// file's users sequence (existing users untouched) and the user is added as a
// member of each named group, creating groups that do not exist yet. Returns an
// error if a user with the same name already exists.
func (c *ConfigRepository) Tell(name string, keys []string, groupsToAdd []string) error {
	users, err := c.Users()
	if err != nil {
		return err
	}

	for _, u := range users {
		if u.Name == name {
			return fmt.Errorf("user %q already exists", name)
		}
	}

	if err := c.appendUser(User{Name: name, Key: keys}); err != nil {
		return err
	}

	for _, group := range groupsToAdd {
		if err := c.addGroupMember(group, name); err != nil {
			return err
		}
	}

	return nil
}

// appendUser inserts u into the main file's users sequence, creating the
// users: key if it is missing.
func (c *ConfigRepository) appendUser(u User) error {
	src := c.MainFile

	seq, err := usersNode(src.RootNode)
	if err != nil {
		// No users: key yet — add the whole sequence as a new top-level key.
		return appendRootKey(src, map[string][]User{"users": {u}})
	}

	newSeq, err := marshalSeq([]User{u})
	if err != nil {
		return fmt.Errorf("%s: building user %q: %w", src.Path, u.Name, err)
	}

	seq.Merge(newSeq)
	return nil
}

// addGroupMember adds member to the named group in the main file's groups
// mapping, creating the groups: key and/or the group itself when missing.
// Members already present are left untouched, so re-saving does not duplicate
// them.
func (c *ConfigRepository) addGroupMember(group, member string) error {
	src := c.MainFile

	groups, err := groupsNode(src.RootNode)
	if err != nil {
		// No groups: key yet — add the whole mapping.
		return appendRootKey(src, map[string]map[string][]string{"groups": {group: {member}}})
	}

	mv := findMappingValue(groups, group)
	if mv == nil {
		newGroup, err := marshalMapping(map[string][]string{group: {member}})
		if err != nil {
			return fmt.Errorf("%s: building group %q: %w", src.Path, group, err)
		}

		groups.Merge(newGroup)
		return nil
	}

	seq, ok := mv.Value.(*ast.SequenceNode)
	if !ok {
		return fmt.Errorf("%s: group %q is not a sequence (got %T)", src.Path, group, mv.Value)
	}

	if err := addMissingMembers(seq, []string{member}); err != nil {
		return fmt.Errorf("%s: group %q: %w", src.Path, group, err)
	}

	return nil
}
