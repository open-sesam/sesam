package config

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"

	"opensesam.org/sesam/util"
)

// State is the declared state of the repository: the normalized projection of
// the config that can be compared against the verified state replayed from the
// audit log.
//
// It carries only what has a counterpart in the audit log. Everything the
// config knows on top of that - descriptions, secret names, rotation and swap
// commands, which file a secret was declared in - is dropped here on purpose:
// those never produce an audit entry, so a diff must not see them.
type State struct {
	Users   []StateUser
	Secrets []StateSecret
}

// StateUser is one entry of users: joined with the group memberships declared
// for it under groups:.
type StateUser struct {
	Name string

	// Groups the user is a member of, sorted and deduplicated.
	Groups []string

	// Keys are the public key specs as written in the config (a literal key, a
	// forge id, a URL or a file path), in declaration order. They are not
	// resolved - resolving is what turns a spec into recorded key material and
	// belongs to the operation that writes the audit entry.
	Keys []string
}

// StateSecret is one declared secret with its path resolved to a
// sesam-relative one.
type StateSecret struct {
	// Path is sesam-relative, i.e. the config's path joined with the directory
	// of the file that declared it. This is the coordinate the audit log's
	// revealed paths use.
	Path string

	// Access is the declared access list, sorted and deduplicated, without the
	// implicit "admin" group.
	Access []string
}

// DuplicateDeclarationError reports a name or path declared more than once.
type DuplicateDeclarationError struct {
	Path string
	Kind string
	Name string
}

func (e *DuplicateDeclarationError) Error() string {
	return fmt.Sprintf("%s: %s %q is declared more than once", e.Path, e.Kind, e.Name)
}

// PathEscapesRepoError reports a secret whose path, resolved against the file
// that declared it, points outside the repository.
type PathEscapesRepoError struct {
	Path     string
	Declared string
	Resolved string
}

func (e *PathEscapesRepoError) Error() string {
	return fmt.Sprintf(
		"%s: secret path %q resolves to %q, which is outside the repository",
		e.Path, e.Declared, e.Resolved,
	)
}

// User returns the declared user by name.
func (s *State) User(name string) (*StateUser, bool) {
	idx := slices.IndexFunc(s.Users, func(u StateUser) bool {
		return u.Name == name
	})
	if idx < 0 {
		return nil, false
	}

	return &s.Users[idx], true
}

// Secret returns the declared secret by its sesam-relative path.
func (s *State) Secret(path string) (*StateSecret, bool) {
	idx := slices.IndexFunc(s.Secrets, func(sec StateSecret) bool {
		return sec.Path == path
	})
	if idx < 0 {
		return nil, false
	}

	return &s.Secrets[idx], true
}

// State derives the declared state from the config. Users and groups come from
// the main file, secrets from the main file and every included one, in include
// order.
//
// Problems that make the declaration ambiguous rather than merely invalid - a
// name or path declared twice, a path escaping the repository - are reported
// here, all of them at once, so a hand-edited file can be fixed in one pass.
// Whether the resulting state is a legal thing to move the repository to is not
// decided here; that is the diff's job.
func (c *Config) State() (*State, error) {
	users, err := c.Users()
	if err != nil {
		return nil, err
	}

	groups, err := c.Groups()
	if err != nil {
		return nil, err
	}

	entries, err := c.secretEntries()
	if err != nil {
		return nil, err
	}

	var problems []error

	// Invert groups: the config declares group -> members, the audit log
	// records the memberships per user. Sorted, so the result does not depend
	// on map iteration order.
	memberOf := map[string][]string{}
	for _, group := range slices.Sorted(maps.Keys(groups)) {
		for _, member := range groups[group] {
			memberOf[member] = append(memberOf[member], group)
		}
	}

	state := &State{
		Users:   make([]StateUser, 0, len(users)),
		Secrets: make([]StateSecret, 0, len(entries)),
	}

	for _, u := range users {
		if _, exists := state.User(u.Name); exists {
			problems = append(problems, &DuplicateDeclarationError{
				Path: c.MainFile.Path,
				Kind: "user",
				Name: u.Name,
			})
			continue
		}

		state.Users = append(state.Users, StateUser{
			Name:   u.Name,
			Groups: util.SortedSet(memberOf[u.Name]),
			Keys:   util.SortedSet(u.Key),
		})
	}

	for _, e := range entries {
		path := filepath.Join(filepath.Dir(e.source.Path), e.secret.Path)
		if !filepath.IsLocal(path) {
			problems = append(problems, &PathEscapesRepoError{
				Path:     e.source.Path,
				Declared: e.secret.Path,
				Resolved: path,
			})
			continue
		}

		if _, exists := state.Secret(path); exists {
			problems = append(problems, &DuplicateDeclarationError{
				Path: e.source.Path,
				Kind: "secret",
				Name: path,
			})
			continue
		}

		state.Secrets = append(state.Secrets, StateSecret{
			Path:   path,
			Access: util.WithoutAdmin(util.SortedSet(e.secret.Access)),
		})
	}

	if err := errors.Join(problems...); err != nil {
		return nil, err
	}

	return state, nil
}
