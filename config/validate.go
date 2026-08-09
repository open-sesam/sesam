package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

// TODO: only allow a specific set of characters for group names and user names
//

// UnknownGroupMemberError reports a name listed under groups: that has no
// matching entry in users:. Such a member silently contributes no keys when
// access is resolved, so a typo would quietly shrink a secret's recipients
// instead of failing.
type UnknownGroupMemberError struct {
	Path  string
	Group string
	User  string
}

func (e *UnknownGroupMemberError) Error() string {
	return fmt.Sprintf("%s: group %q lists unknown user %q", e.Path, e.Group, e.User)
}

// Validate reports semantic problems the JSON schema cannot express. The schema
// constrains the shape of a single file; Validate checks meaning across the
// whole config.
//
// Every problem is reported, not just the first, so a hand-edited file can be
// fixed in one pass. Users and groups are declared in the main file only, so
// that is the only file consulted.
func (c *Config) Validate() error {
	if c.MainFile == nil {
		return nil
	}

	users, err := c.Users()
	if err != nil {
		return err
	}

	groups, err := c.Groups()
	if err != nil {
		return err
	}

	known := make(map[string]bool, len(users))
	for _, u := range users {
		known[u.Name] = true
	}

	var problems []error

	// Sorted, because map iteration would otherwise shuffle the report between
	// runs. Members keep their declaration order.
	for _, group := range slices.Sorted(maps.Keys(groups)) {
		for _, member := range groups[group] {
			if !known[member] {
				problems = append(problems, &UnknownGroupMemberError{
					Path:  c.MainFile.Path,
					Group: group,
					User:  member,
				})
			}
		}
	}

	return errors.Join(problems...)
}
