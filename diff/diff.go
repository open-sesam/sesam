// Package diff compares the verified state of a sesam repository (replayed
// from the audit log) against the state declared in sesam.yml.
//
// The comparison is pure: it touches no file, no network and no git. Whether a
// declared secret actually exists on disk, whether a key spec still resolves to
// the recorded material, and whether the config change is allowed to be applied
// at all (see the "invalid modified config" attack in the design document) are
// all decisions for the applying side.
//
// The audit log stays authoritative throughout: the declaration is a request,
// never a truth.
package diff

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"opensesam.org/sesam/config"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/util"
)

// maxUserKeys mirrors the limit the audit log enforces when a user is
// registered. Checking it here turns a mid-apply verification failure into a
// config error reported before anything is written.
const maxUserKeys = 10

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
	Groups []string `json:"groups,omitempty"`

	// Keys are public key specs to add for user.tell and user.add_recipients.
	// For user.rm_recipients it is the recorded key material instead of the
	// spec it came from - the material is a valid spec in its own right and
	// matches the stored recipient exactly, so a forge whose contents changed
	// in the meantime cannot make the removal miss.
	Keys []string `json:"keys,omitempty"`

	// Old is the set being replaced, for the change operations. Purely
	// informational, meant for rendering the diff.
	Old []string `json:"old,omitempty"`
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

// Compute diffs the declared state against the verified one and returns the
// changes needed to make the verified state match the declaration, ordered so
// that applying them in sequence never passes through a state the audit log
// would reject.
//
// Renames are not detected. Nothing in the verified state survives a rename to
// pair the old name with the new one, so a renamed user or a moved secret path
// shows up as a removal plus an addition. `sesam user rename` and
// `sesam secret move` stay the explicit route for those.
//
// A declaration the repository could not legally be moved to - a user in no
// group, a config without any admin - is an error rather than a set of
// changes, and every such problem is reported at once.
func Compute(vstate *core.VerifiedState, declared *config.State) (*Diff, error) {
	if err := validate(vstate, declared); err != nil {
		return nil, err
	}

	changes := append(userChanges(vstate, declared), secretChanges(vstate, declared)...)
	slices.SortStableFunc(changes, compareChanges)

	return &Diff{Changes: changes}, nil
}

// validate rejects declarations that cannot be applied at all, in the terms the
// audit log's own verification uses. Checks that depend on the world outside
// the two states (does the secret exist on disk, does the spec still resolve)
// are left to the applying side.
func validate(vstate *core.VerifiedState, declared *config.State) error {
	var problems []error

	admins := 0
	for _, du := range declared.Users {
		if slices.Contains(du.Groups, "admin") {
			admins++
		}

		if _, exists := vstate.UserExists(du.Name); !exists {
			if err := core.ValidUserName(du.Name); err != nil {
				problems = append(problems, fmt.Errorf("invalid user name %q: %w", du.Name, err))
			}
		}

		// The audit log refuses to register a user without a group and refuses
		// to change an existing user to zero groups, so an ungrouped user is
		// never appliable - not even as a no-op.
		if len(du.Groups) == 0 {
			problems = append(problems, fmt.Errorf(
				"user %q is in no group: add them to a group under groups", du.Name,
			))
		}

		switch {
		case len(du.Keys) == 0:
			problems = append(problems, fmt.Errorf("user %q has no key", du.Name))
		case len(du.Keys) > maxUserKeys:
			problems = append(problems, fmt.Errorf(
				"user %q has %d keys, at most %d are allowed", du.Name, len(du.Keys), maxUserKeys,
			))
		}
	}

	if admins == 0 {
		problems = append(problems, errors.New(
			"config declares no admin user: at least one user must be a member of the admin group",
		))
	}

	for _, ds := range declared.Secrets {
		if _, exists := vstate.SecretExists(ds.Path); exists {
			// Already tracked, so it passed these checks when it was added.
			continue
		}

		if err := core.IsForbiddenPath(ds.Path); err != nil {
			problems = append(problems, fmt.Errorf("secret %q: %w", ds.Path, err))
		}
	}

	return errors.Join(problems...)
}

// userChanges diffs the declared users against the verified ones.
func userChanges(vstate *core.VerifiedState, declared *config.State) []Change {
	var changes []Change

	for _, du := range declared.Users {
		vu, exists := vstate.UserExists(du.Name)
		// "admin" is a group like any other for a user - only secrets carry it
		// implicitly - so the declared set is taken as is, just made stable.
		groups := slices.Compact(du.Groups)

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
				Old:    slices.Compact(vu.Groups),
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
		// The verified access list always carries "admin". Drop it on the
		// declared side too, so spelling out the implicit group is neither a
		// change nor something that ends up in the payload.
		access := util.WithoutAdmin(slices.Compact(ds.Access))

		vs, exists := vstate.SecretExists(ds.Path)
		if !exists {
			changes = append(changes, Change{
				Op:     core.OpSecretAdd,
				Path:   ds.Path,
				Groups: access,
			})
			continue
		}

		if !sameSet(vs.DeclaredGroups(), access) {
			changes = append(changes, Change{
				Op:     core.OpSecretChangeAccess,
				Path:   ds.Path,
				Groups: access,
				Old:    slices.Compact(vs.DeclaredGroups()),
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
//
// A recipient matches a spec either by its source (the spec it was resolved
// from, e.g. "github:alice") or by its key material (a spec written verbatim in
// the config). Matching both ways keeps the diff convergent when the same key
// is declared under two spec forms, which the audit log collapses into a single
// recipient carrying only one of them as its source.
//
// Comparing sources rather than resolving the specs means a forge whose
// contents changed since the key was recorded produces no change here. That is
// deliberate: pinning is what makes the recorded key trustworthy, and surfacing
// the drift is `sesam verify --forge`'s job.
func recipientDelta(recps core.Recipients, specs []string) (add, remove []string) {
	matches := func(r *core.Recipient, spec string) bool {
		return string(r.Source) == spec || r.String() == spec
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

// compareChanges orders changes by their operation (see opRank), then by the
// user or secret they touch so the result is stable.
func compareChanges(a, b Change) int {
	if c := opRank[a.Op] - opRank[b.Op]; c != 0 {
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

// list renders a set for the one-line change rendering.
func list(s []string) string {
	if len(s) == 0 {
		return "-"
	}

	return strings.Join(s, ", ")
}
