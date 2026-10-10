package config

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"

	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo/util"
)

// State is the declared state of the repository: the normalized projection of
// the config that can be compared against the verified state replayed from the
// audit log.
type State = core.BaseState[StateUser]

// StateUser is one entry of users: joined with the group memberships declared
// for it under groups:. What it adds to the shared membership is the one thing
// a config states differently from the audit log: keys as specs rather than as
// resolved recipients.
type StateUser struct {
	core.Membership

	// Keys are the public key specs as written in the config in declaration order.
	// They are not resolved - resolving is what turns a spec into recorded key material and
	// belongs to the operation that writes the audit entry.
	Keys []string
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
		Secrets: make([]core.SecretAccess, 0, len(entries)),
	}

	// Duplicate checks use their own maps rather than state.User()/state.Secret():
	// those lazily cache an index from whatever is in state.Users/state.Secrets at
	// first call, which here is a work-in-progress slice still being appended to.
	seenUsers := make(map[string]bool, len(users))
	seenSecrets := make(map[string]bool, len(entries))

	for _, u := range users {
		if seenUsers[u.Name] {
			problems = append(problems, &DuplicateDeclarationError{
				Path: c.MainFile.Path,
				Kind: "user",
				Name: u.Name,
			})
			continue
		}
		seenUsers[u.Name] = true

		state.Users = append(state.Users, StateUser{
			Membership: core.Membership{
				Name:   u.Name,
				Groups: util.SortedSet(memberOf[u.Name]),
			},
			Keys: util.SortedSet(u.Key),
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

		if seenSecrets[path] {
			problems = append(problems, &DuplicateDeclarationError{
				Path: e.source.Path,
				Kind: "secret",
				Name: path,
			})
			continue
		}
		seenSecrets[path] = true

		state.Secrets = append(state.Secrets, core.SecretAccess{
			RevealedPath: path,
			// Normalized the way the audit log records it: "admin" is
			// implicit in the file and explicit here, so the declared and
			// the verified access list compare as they are.
			AccessGroups: util.WithAdmin(e.secret.Access),
		})
	}

	if err := errors.Join(problems...); err != nil {
		return nil, err
	}

	return state, nil
}
