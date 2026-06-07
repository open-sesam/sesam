package config

import (
	"fmt"
	"slices"
)

// Tell adds a new user to the main sesam.yml: a name, one or more keys and the
// groups the user should belong to. The user is appended to the main file's
// users list (Save writes only this new entry, leaving existing users intact)
// and added as a member of each named group, creating groups that do not exist
// yet. Returns an error if a user with the same name already exists.
func (c *ConfigRepository) Tell(name string, keys []string, groupsToAdd []string) error {
	for _, u := range c.MainFile.Config.Users {
		if u.Name == name {
			return fmt.Errorf("user %q already exists", name)
		}
	}

	c.MainFile.Config.Users = append(c.MainFile.Config.Users, User{
		Name: name,
		Key:  keys,
	})

	if c.MainFile.Config.Groups == nil {
		c.MainFile.Config.Groups = map[string][]string{}
	}

	for _, group := range groupsToAdd {
		if slices.Contains(c.MainFile.Config.Groups[group], name) {
			continue
		}

		c.MainFile.Config.Groups[group] = append(c.MainFile.Config.Groups[group], name)
	}

	return nil
}
