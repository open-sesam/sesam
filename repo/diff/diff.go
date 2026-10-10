// Package diff compares the verified state of a sesam repository (replayed
// from the audit log) against the state declared in sesam.yml.
package diff

import (
	"fmt"
	"slices"
	"strings"

	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo/config"
	"opensesam.org/sesam/repo/util"
)

// Change is one operation that would move the verified state a step towards the
// declared state. It names an operation of the audit log, but is deliberately
// phrased in terms of what the caller has to invoke rather than as a ready-made
// audit entry: applying a user.tell also generates a signing key, rewrites the
// audit key and resolves key specs over the network, none of which a pure diff
// can produce.
type Change struct {
	// Op is the audit-log operation this change corresponds to.
	Op core.Operation `json:"op"`

	// User is set for the user operations, Path (sesam-relative) for the
	// secret ones.
	User string `json:"user,omitempty"`
	Path string `json:"path,omitempty"`

	// Groups is the declared target set: the user's new groups for
	// user.change_groups and user.tell, the secret's new access list (without
	// the implicit "admin") for secret.add and secret.change_access.
	Groups []string `json:"groups"`

	// Keys are public key specs to add for user.tell and user.add_recipients.
	// For user.rm_recipients it is the recorded key material instead of the
	// spec it came from - the material is a valid spec in its own right and
	// matches the stored recipient exactly, so a forge whose contents changed
	// in the meantime cannot make the removal miss.
	Keys []string `json:"keys,omitempty"`

	// Old is the set being replaced by Groups, for user.change_groups and
	// secret.change_access. Purely informational, meant for rendering the
	// diff.
	Old []string `json:"old"`
}

// Diff is the ordered set of changes between the verified and the declared
// state. Empty means the two agree.
type Diff struct {
	Changes []Change
}

// String renders a change as a single line, in the spirit of a unified diff:
// "+" adds, "-" removes, "~" changes.
func (c Change) String() string {
	switch c.Op {
	case core.OpUserTell:
		return fmt.Sprintf("+ user %s (groups: %s, keys: %s)", c.User, list(c.Groups), list(c.Keys))
	case core.OpUserKill:
		return fmt.Sprintf("- user %s", c.User)
	case core.OpUserChangeGroups:
		return fmt.Sprintf("~ user %s groups: %s -> %s", c.User, list(c.Old), list(c.Groups))
	case core.OpUserAddRecipients:
		return fmt.Sprintf("+ keys of user %s: %s", c.User, list(c.Keys))
	case core.OpUserRmRecipients:
		return fmt.Sprintf("- keys of user %s: %s", c.User, list(c.Keys))
	case core.OpSecretAdd:
		return fmt.Sprintf("+ secret %s (access: %s)", c.Path, list(c.Groups))
	case core.OpSecretRemove:
		return fmt.Sprintf("- secret %s", c.Path)
	case core.OpSecretChangeAccess:
		return fmt.Sprintf("~ secret %s access: %s -> %s", c.Path, list(c.Old), list(c.Groups))
	default:
		return fmt.Sprintf("? unexpected core.Operation: %#v", c.Op)
	}
}

// Equal reports whether two changes describe the same step. Old is left out of
// the comparison: it records what the step replaces, which both sides read from
// the same verified state, and carries no intent of its own.
func (c Change) Equal(other Change) bool {
	return c.Op == other.Op &&
		c.User == other.User &&
		c.Path == other.Path &&
		sameSet(c.Groups, other.Groups) &&
		sameSet(c.Keys, other.Keys)
}

// Conflicts reports whether c and other are the same operation on the same
// user or path and grant an overlapping payload - any group or key one of
// them declares, the other does too. Old is left out, same as Equal.
func (c Change) Conflicts(other Change) bool {
	if c.Op != other.Op || c.User != other.User || c.Path != other.Path {
		return false
	}

	if len(c.Groups) == 0 && len(other.Groups) == 0 && len(c.Keys) == 0 && len(other.Keys) == 0 {
		// Neither side carries a payload (OpUserKill, OpSecretRemove): Op,
		// User and Path already fully identify the step.
		return true
	}

	return intersects(c.Groups, other.Groups) || intersects(c.Keys, other.Keys)
}

// IsEmpty reports whether the declared and the verified state agree.
func (d *Diff) IsEmpty() bool {
	return len(d.Changes) == 0
}

// String renders the whole diff, one change per line.
func (d *Diff) String() string {
	lines := make([]string, 0, len(d.Changes))
	for _, c := range d.Changes {
		lines = append(lines, c.String())
	}

	return strings.Join(lines, "\n")
}

// Delta diffs the declared state against the verified one and returns the
// changes needed to make the verified state match the declaration. Ordered so
// that applying them in sequence never passes through a state the audit log
// would reject. Whether the declaration is appliable at all is left to the
// audit log itself, as each change is fed to it.
func Delta(vstate *core.VerifiedState, declared *config.State) *Diff {
	users := userChanges(vstate, declared)
	secrets := secretChanges(vstate, declared)

	// Built rather than appended onto one of the two, so the result is never
	// nil: "no changes" renders as [] and not null for the JSON callers.
	changes := make([]Change, 0, len(users)+len(secrets))
	changes = append(changes, users...)
	changes = append(changes, secrets...)
	slices.SortStableFunc(changes, compareChanges)

	return &Diff{Changes: changes}
}

// userChanges diffs the declared users against the verified ones.
func userChanges(vstate *core.VerifiedState, declared *config.State) []Change {
	var changes []Change

	for _, du := range declared.Users {
		vu, exists := vstate.UserExists(du.Name)
		// "admin" is a group like any other for a user - only secrets carry it
		// implicitly - so the declared set is taken as is, just made stable.
		// Compact mutates in place, and vu points into the caller's
		// VerifiedState, so both sides are cloned first - a pure diff must not
		// leave the verified state's own group slice reordered behind it.
		groups := slices.Compact(slices.Clone(du.Groups))

		if !exists {
			changes = append(changes, Change{
				Op:     core.OpUserTell,
				User:   du.Name,
				Groups: groups,
				Keys:   du.Keys,
			})
			continue
		}

		if !sameSet(vu.Groups, groups) {
			changes = append(changes, Change{
				Op:     core.OpUserChangeGroups,
				User:   du.Name,
				Groups: groups,
				Old:    slices.Compact(slices.Clone(vu.Groups)),
			})
		}

		add, remove := recipientDelta(vu.Recps, du.Keys)
		if len(add) > 0 {
			changes = append(changes, Change{
				Op:   core.OpUserAddRecipients,
				User: du.Name,
				Keys: add,
			})
		}
		if len(remove) > 0 {
			changes = append(changes, Change{
				Op:   core.OpUserRmRecipients,
				User: du.Name,
				Keys: remove,
			})
		}
	}

	for _, vu := range vstate.Users {
		if _, exists := declared.User(vu.Name); !exists {
			changes = append(changes, Change{Op: core.OpUserKill, User: vu.Name})
		}
	}

	return changes
}

// secretChanges diffs the declared secrets against the verified ones.
func secretChanges(vstate *core.VerifiedState, declared *config.State) []Change {
	var changes []Change

	for _, ds := range declared.Secrets {
		// Both sides carry the implicit "admin" group, so the access lists
		// compare as they are. The payload drops it again: that is the form a
		// config persists and an audit entry records.
		vs, exists := vstate.SecretExists(ds.RevealedPath)
		if !exists {
			changes = append(changes, Change{
				Op:     core.OpSecretAdd,
				Path:   ds.RevealedPath,
				Groups: ds.DeclaredGroups(),
			})
			continue
		}

		if !sameSet(vs.AccessGroups, ds.AccessGroups) {
			changes = append(changes, Change{
				Op:     core.OpSecretChangeAccess,
				Path:   ds.RevealedPath,
				Groups: ds.DeclaredGroups(),
				Old:    vs.DeclaredGroups(),
			})
		}
	}

	for _, vs := range vstate.Secrets {
		if _, exists := declared.Secret(vs.RevealedPath); !exists {
			changes = append(changes, Change{Op: core.OpSecretRemove, Path: vs.RevealedPath})
		}
	}

	return changes
}

// recipientDelta pairs a user's declared key specs with the recipients recorded
// for them in the audit log.
func recipientDelta(recps core.Recipients, specs []string) (add, remove []string) {
	matches := func(r *core.Recipient, spec string) bool {
		return r.Spec() == spec || r.String() == core.CanonicalKeySpec(spec)
	}

	for _, spec := range specs {
		known := slices.ContainsFunc(recps, func(r *core.Recipient) bool {
			return matches(r, spec)
		})
		if !known {
			add = append(add, spec)
		}
	}

	for _, r := range recps {
		declared := slices.ContainsFunc(specs, func(spec string) bool {
			return matches(r, spec)
		})
		if !declared {
			remove = append(remove, r.String())
		}
	}

	return add, remove
}

// opRank orders the changes so that no intermediate state is rejected by the
// audit log. Every entry is verified as it is fed, so an order that dips
// through an invalid state fails half-way applied. Additions therefore come
// before removals throughout: a new admin is told before the old one is
// demoted or killed, and a user gains their new keys before losing the old
// ones (a user may never end up with zero recipients).
var opRank = map[core.Operation]int{
	core.OpUserTell:           0,
	core.OpUserAddRecipients:  1,
	core.OpUserChangeGroups:   2,
	core.OpSecretAdd:          3,
	core.OpSecretChangeAccess: 4,
	core.OpSecretRemove:       5,
	core.OpUserRmRecipients:   6,
	core.OpUserKill:           7,
}

// rankOf returns op's position in opRank, or one past the worst known rank for
// an operation opRank does not recognise - never rank 0, which a plain map
// lookup would silently produce and which would sort an unknown operation as
// if it were OpUserTell, first and safest.
func rankOf(op core.Operation) int {
	if rank, ok := opRank[op]; ok {
		return rank
	}

	return len(opRank)
}

// compareChanges orders changes by their operation (see opRank), then by the
// user or secret they touch so the result is stable.
func compareChanges(a, b Change) int {
	if c := rankOf(a.Op) - rankOf(b.Op); c != 0 {
		return c
	}

	// Within the group changes, promotions come before demotions: dropping the
	// last admin is rejected, so whoever gains admin has to gain it first.
	if a.Op == core.OpUserChangeGroups {
		if c := adminRank(a) - adminRank(b); c != 0 {
			return c
		}
	}

	if c := strings.Compare(a.User, b.User); c != 0 {
		return c
	}

	return strings.Compare(a.Path, b.Path)
}

// adminRank sorts a change that keeps or grants admin before one that drops it.
func adminRank(c Change) int {
	if slices.Contains(c.Groups, "admin") {
		return 0
	}

	return 1
}

// sameSet reports whether a and b hold the same elements, ignoring order and
// duplicates.
func sameSet(a, b []string) bool {
	return slices.Equal(util.SortedSet(a), util.SortedSet(b))
}

// intersects reports whether a and b share at least one element.
func intersects(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}

	return false
}

// list renders a set for the one-line change rendering.
func list(s []string) string {
	if len(s) == 0 {
		return "-"
	}

	return strings.Join(s, ", ")
}
