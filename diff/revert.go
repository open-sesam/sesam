package diff

import (
	"fmt"
	"slices"

	"opensesam.org/sesam/config"
	"opensesam.org/sesam/core"
)

// Revert backs the declared changes out of cfg, turning it into a config that
// describes the verified state instead.
//
// Together with the config it was computed from, that gives the two sides of a
// config diff: the file as the user wrote it, and the same file as the audit
// log sees it - same comments, same formatting, same include structure,
// differing only where the declaration does.
//
// cfg must be the config the diff was computed from (or a copy of it) and
// vstate the state it was compared against: putting back a killed user or a
// removed secret needs the keys, groups and access lists that only the
// verified state still knows.
//
// Nothing is written here - the AST is edited in memory. Note though that some
// config mutators delete a sub-file their last secret left empty, so callers
// must hand this a config rooted at a *copy* of the tree, never the live one.
func Revert(cfg *config.Config, vstate *core.VerifiedState, d *Diff) error {
	// Undo in reverse: the forward plan deliberately adds before it removes, so
	// walking it backwards never has to remove something a later step puts
	// back. That matters for a user's keys, where the config refuses to leave
	// none behind.
	for i := len(d.Changes) - 1; i >= 0; i-- {
		change := d.Changes[i]
		if err := revert(cfg, vstate, change); err != nil {
			return fmt.Errorf("revert %s: %w", change.Op, err)
		}
	}

	return nil
}

// revert undoes a single change. The direction reads inverted on purpose: a
// change that would tell a user is undone by removing them from the config,
// and one that would kill a user by declaring them again as recorded.
func revert(cfg *config.Config, vstate *core.VerifiedState, c Change) error {
	switch c.Op {
	case core.OpUserTell:
		return cfg.UserKill(c.User)

	case core.OpUserKill:
		user, err := verifiedUser(vstate, c.User)
		if err != nil {
			return err
		}
		return cfg.UserTell(user.Name, user.Recps.Specs(), user.Groups)

	case core.OpUserChangeGroups:
		return cfg.UserChangeGroups(c.User, c.Old)

	case core.OpUserAddRecipients:
		return cfg.UserRmRecipient(c.User, c.Keys)

	case core.OpUserRmRecipients:
		user, err := verifiedUser(vstate, c.User)
		if err != nil {
			return err
		}
		// The change carries recorded key material; put the keys back in the
		// spec form the config would have used for them, so a key resolved
		// from a forge reappears as that forge id and not as raw material.
		return cfg.UserAddRecipient(c.User, specsForKeys(user.Recps, c.Keys))

	case core.OpSecretAdd:
		return cfg.SecretRemove(c.Path)

	case core.OpSecretRemove:
		secret, exists := vstate.SecretExists(c.Path)
		if !exists {
			return fmt.Errorf("secret %q is not in the verified state", c.Path)
		}
		return cfg.SecretAdd(c.Path, false, secret.DeclaredGroups())

	case core.OpSecretChangeAccess:
		return cfg.SecretChangeGroups(c.Path, c.Old)

	default:
		return fmt.Errorf("unexpected core.Operation: %#v", c.Op)
	}
}

func verifiedUser(vstate *core.VerifiedState, name string) (*core.VerifiedUser, error) {
	user, exists := vstate.UserExists(name)
	if !exists {
		return nil, fmt.Errorf("user %q is not in the verified state", name)
	}

	return user, nil
}

// specsForKeys maps recorded key material back to the spec form of the
// recipient holding it, leaving anything it cannot find as it came in.
func specsForKeys(recps core.Recipients, keys []string) []string {
	specs := make([]string, 0, len(keys))
	for _, key := range keys {
		spec := key
		if idx := slices.IndexFunc(recps, func(r *core.Recipient) bool {
			return r.String() == key
		}); idx >= 0 {
			spec = recps[idx].Spec()
		}

		if !slices.Contains(specs, spec) {
			specs = append(specs, spec)
		}
	}

	return specs
}
