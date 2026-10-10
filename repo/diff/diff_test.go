package diff

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"slices"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo/config"
	"opensesam.org/sesam/repo/util"
)

// newRecipient returns a freshly generated recipient carrying source, i.e. one
// entry of a verified user's key list as the audit log would have recorded it.
func newRecipient(t *testing.T, source core.KeySource) *core.Recipient {
	t.Helper()

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	recp, err := core.ParseRecipient(id.Recipient().String(), nil)
	require.NoError(t, err)

	recp.Source = source
	return recp
}

// newSSHRecipient returns a freshly generated, manually given ssh recipient.
func newSSHRecipient(t *testing.T) *core.Recipient {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	recp, err := core.ParseRecipient(string(ssh.MarshalAuthorizedKey(sshPub)), nil)
	require.NoError(t, err)

	return recp
}

// verifiedState builds a state the way core hands one out: with its lookup
// indexes in place. A bare literal answers "not found" to every lookup, so
// every hand-built state in these tests goes through here.
func verifiedState(users []core.VerifiedUser, secrets []core.SecretAccess) *core.VerifiedState {
	state := &core.VerifiedState{Users: users, Secrets: secrets}
	state.BuildIndexes()

	return state
}

// declaredSecret builds a declared secret the way config.State does, with the
// implicit admin group spelled out.
func declaredSecret(path string, access ...string) core.SecretAccess {
	return core.SecretAccess{
		RevealedPath: path,
		AccessGroups: util.WithAdmin(access),
	}
}

// verifiedSecret is the same for the audit-log side, where admin is spelled
// out too.
func verifiedSecret(path string, access ...string) core.SecretAccess {
	return core.SecretAccess{
		RevealedPath: path,
		AccessGroups: util.WithAdmin(access),
	}
}

// admin is the verified admin every scenario needs: killing or demoting the
// last admin is rejected, so a declaration without one is not appliable.
func admin(t *testing.T) core.VerifiedUser {
	t.Helper()

	return core.VerifiedUser{Membership: core.Membership{Name: "alice", Groups: []string{"admin"}}, Recps: core.Recipients{newRecipient(t, "github:alice")}}
}

// declaredAdmin is the declaration matching admin(t).
func declaredAdmin() config.StateUser {
	return config.StateUser{Membership: core.Membership{Name: "alice", Groups: []string{"admin"}}, Keys: []string{"github:alice"}}
}

// ops reduces a diff to the operations it proposes, in order.
func ops(d *Diff) []core.Operation {
	out := make([]core.Operation, 0, len(d.Changes))
	for _, c := range d.Changes {
		out = append(out, c.Op)
	}

	return out
}

func TestDeltaInSync(t *testing.T) {
	alice := admin(t)
	vstate := verifiedState(
		[]core.VerifiedUser{alice},
		[]core.SecretAccess{verifiedSecret("db.env", "dev")},
	)

	declared := &config.State{
		Users: []config.StateUser{declaredAdmin()},
		Secrets: []core.SecretAccess{
			// "admin" is implicit in the file and spelled out here, and the
			// order differs: neither is a change.
			declaredSecret("db.env", "dev"),
		},
	}

	got := Delta(vstate, declared)
	require.True(t, got.IsEmpty(), got.String())
}

func TestDeltaUsers(t *testing.T) {
	bobKey := newRecipient(t, core.KeySourceManual)
	oldKey := newRecipient(t, "github:bob")

	tests := []struct {
		name     string
		user     *core.VerifiedUser
		declared *config.StateUser
		want     []Change
	}{
		{
			name:     "new user is told",
			declared: &config.StateUser{Membership: core.Membership{Name: "bob", Groups: []string{"dev"}}, Keys: []string{"github:bob"}},
			want: []Change{{
				Op:     core.OpUserTell,
				User:   "bob",
				Groups: []string{"dev"},
				Keys:   []string{"github:bob"},
			}},
		},
		{
			name: "undeclared user is killed",
			user: &core.VerifiedUser{Membership: core.Membership{Name: "bob", Groups: []string{"dev"}}, Recps: core.Recipients{bobKey}},
			want: []Change{{Op: core.OpUserKill, User: "bob"}},
		},
		{
			name:     "changed group membership",
			user:     &core.VerifiedUser{Membership: core.Membership{Name: "bob", Groups: []string{"dev"}}, Recps: core.Recipients{oldKey}},
			declared: &config.StateUser{Membership: core.Membership{Name: "bob", Groups: []string{"dev", "ops"}}, Keys: []string{"github:bob"}},
			want: []Change{{
				Op:     core.OpUserChangeGroups,
				User:   "bob",
				Groups: []string{"dev", "ops"},
				Old:    []string{"dev"},
			}},
		},
		{
			name:     "reordered groups are no change",
			user:     &core.VerifiedUser{Membership: core.Membership{Name: "bob", Groups: []string{"ops", "dev"}}, Recps: core.Recipients{oldKey}},
			declared: &config.StateUser{Membership: core.Membership{Name: "bob", Groups: []string{"dev", "ops"}}, Keys: []string{"github:bob"}},
		},
		{
			name:     "key swapped: the new one is added before the old one goes",
			user:     &core.VerifiedUser{Membership: core.Membership{Name: "bob", Groups: []string{"dev"}}, Recps: core.Recipients{oldKey}},
			declared: &config.StateUser{Membership: core.Membership{Name: "bob", Groups: []string{"dev"}}, Keys: []string{bobKey.String()}},
			want: []Change{
				{Op: core.OpUserAddRecipients, User: "bob", Keys: []string{bobKey.String()}},
				// Removal carries the recorded material, not the source spec.
				{Op: core.OpUserRmRecipients, User: "bob", Keys: []string{oldKey.String()}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			users := []core.VerifiedUser{admin(t)}
			if tc.user != nil {
				users = append(users, *tc.user)
			}
			vstate := verifiedState(users, nil)

			declared := &config.State{Users: []config.StateUser{declaredAdmin()}}
			if tc.declared != nil {
				declared.Users = append(declared.Users, *tc.declared)
			}

			got := Delta(vstate, declared)
			require.Equal(t, tc.want, nilIfEmpty(got.Changes))
		})
	}
}

func TestDeltaSecrets(t *testing.T) {
	tests := []struct {
		name     string
		secret   *core.SecretAccess
		declared *core.SecretAccess
		want     []Change
	}{
		{
			name:     "new secret is added",
			declared: ptr(declaredSecret("db.env", "dev")),
			want: []Change{{
				Op:     core.OpSecretAdd,
				Path:   "db.env",
				Groups: []string{"dev"},
			}},
		},
		{
			name:   "undeclared secret is removed",
			secret: ptr(verifiedSecret("db.env", "dev")),
			want:   []Change{{Op: core.OpSecretRemove, Path: "db.env"}},
		},
		{
			name:     "changed access",
			secret:   ptr(verifiedSecret("db.env", "dev")),
			declared: ptr(declaredSecret("db.env", "ops")),
			want: []Change{{
				Op:     core.OpSecretChangeAccess,
				Path:   "db.env",
				Groups: []string{"ops"},
				Old:    []string{"dev"},
			}},
		},
		{
			name:     "admin declared explicitly is no change",
			secret:   ptr(verifiedSecret("db.env", "dev")),
			declared: ptr(declaredSecret("db.env", "admin", "dev")),
		},
		{
			name:     "dropping access to admin only",
			secret:   ptr(verifiedSecret("db.env", "dev")),
			declared: ptr(declaredSecret("db.env")),
			want: []Change{{
				Op:     core.OpSecretChangeAccess,
				Path:   "db.env",
				Groups: []string{},
				Old:    []string{"dev"},
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var secrets []core.SecretAccess
			if tc.secret != nil {
				secrets = append(secrets, *tc.secret)
			}
			vstate := verifiedState([]core.VerifiedUser{admin(t)}, secrets)

			declared := &config.State{Users: []config.StateUser{declaredAdmin()}}
			if tc.declared != nil {
				declared.Secrets = append(declared.Secrets, *tc.declared)
			}

			got := Delta(vstate, declared)
			require.Equal(t, tc.want, nilIfEmpty(got.Changes))
		})
	}
}

// TestDeltaRecipientMatching covers the spec-to-recipient pairing. The
// central property is convergence: a declaration the audit log already
// satisfies must produce no change, however the key was spelled.
func TestDeltaRecipientMatching(t *testing.T) {
	forge := newRecipient(t, "github:bob")
	manual := newRecipient(t, core.KeySourceManual)
	sshKey := newSSHRecipient(t)

	tests := []struct {
		name  string
		recps core.Recipients
		keys  []string
		want  []Change
	}{
		{
			name:  "forge spec matches the source it was resolved from",
			recps: core.Recipients{forge},
			keys:  []string{"github:bob"},
		},
		{
			name:  "literal key matches the recorded material",
			recps: core.Recipients{manual},
			keys:  []string{manual.String()},
		},
		{
			name: "verbatim ssh key matches with its comment",
			// The audit log records ssh keys without their comment, so a
			// pasted `id_ed25519.pub` must not stay a diff forever.
			recps: core.Recipients{sshKey},
			keys:  []string{sshKey.String() + " bob@laptop"},
		},
		{
			name: "one key declared under two spec forms",
			// The audit log collapses these into a single recipient keeping
			// only one source, so matching on the source alone would propose
			// the same addition on every run.
			recps: core.Recipients{forge},
			keys:  []string{"github:bob", forge.String()},
		},
		{
			name:  "a forge resolving to several keys is covered by one spec",
			recps: core.Recipients{forge, newRecipient(t, "github:bob")},
			keys:  []string{"github:bob"},
		},
		{
			name:  "an added spec is proposed as-is, not resolved",
			recps: core.Recipients{forge},
			keys:  []string{"github:bob", "https://example.com/key.pub"},
			want: []Change{{
				Op:   core.OpUserAddRecipients,
				User: "bob",
				Keys: []string{"https://example.com/key.pub"},
			}},
		},
		{
			name: "a spec literally 'manual' must not match a manually-keyed recipient by sentinel",
			// Regression: matching on the raw KeySource once made a declared
			// spec of "manual" match every manually-sourced recipient
			// regardless of its actual material, silently absorbing a
			// revocation (config diff said "in sync" while the key stayed a
			// recipient).
			recps: core.Recipients{manual},
			keys:  []string{"manual"},
			want: []Change{
				{Op: core.OpUserAddRecipients, User: "bob", Keys: []string{"manual"}},
				{Op: core.OpUserRmRecipients, User: "bob", Keys: []string{manual.String()}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vstate := verifiedState([]core.VerifiedUser{
				admin(t),
				{Name: "bob", Groups: []string{"dev"}, Recps: tc.recps},
			}, nil)

			declared := &config.State{Users: []config.StateUser{
				declaredAdmin(),
				{Name: "bob", Groups: []string{"dev"}, Keys: tc.keys},
			}}

			got := Delta(vstate, declared)
			require.Equal(t, tc.want, nilIfEmpty(got.Changes))
		})
	}
}

// TestDeltaOrdering checks that a plan touching everything at once is ordered
// so no intermediate state is one the audit log would reject: the new admin is
// told before the old one is demoted and killed, and secrets are added before
// the users losing access disappear.
func TestDeltaOrdering(t *testing.T) {
	vstate := verifiedState(
		[]core.VerifiedUser{
			{
				Name:   "alice",
				Groups: []string{"admin"},
				Recps:  core.Recipients{newRecipient(t, "github:alice")},
			},
			{
				Name:   "mallory",
				Groups: []string{"dev"},
				Recps:  core.Recipients{newRecipient(t, "github:mallory")},
			},
		},
		[]core.SecretAccess{
			verifiedSecret("old.env", "dev"),
			verifiedSecret("db.env", "dev"),
		},
	)

	declared := &config.State{
		Users: []config.StateUser{
			// alice hands the admin role to bob, who does not exist yet.
			{Membership: core.Membership{Name: "alice", Groups: []string{"dev"}}, Keys: []string{"github:alice"}},
			{Membership: core.Membership{Name: "bob", Groups: []string{"admin"}}, Keys: []string{"github:bob"}},
		},
		Secrets: []core.SecretAccess{
			declaredSecret("db.env", "ops"),
			declaredSecret("new.env", "dev"),
		},
	}

	got := Delta(vstate, declared)
	require.Equal(t, []core.Operation{
		core.OpUserTell,           // bob, so an admin exists before alice steps down
		core.OpUserChangeGroups,   // alice: admin -> dev
		core.OpSecretAdd,          // new.env
		core.OpSecretChangeAccess, // db.env
		core.OpSecretRemove,       // old.env
		core.OpUserKill,           // mallory
	}, ops(got), got.String())
}

// TestDeltaOrderingPromotionBeforeDemotion checks the ordering within
// user.change_groups itself: whoever gains admin must gain it before the
// current admin drops it, or the audit log rejects the demotion.
func TestDeltaOrderingPromotionBeforeDemotion(t *testing.T) {
	vstate := verifiedState([]core.VerifiedUser{
		{Name: "alice", Groups: []string{"admin"}, Recps: core.Recipients{newRecipient(t, "github:alice")}},
		{Name: "bob", Groups: []string{"dev"}, Recps: core.Recipients{newRecipient(t, "github:bob")}},
	}, nil)

	declared := &config.State{Users: []config.StateUser{
		{Membership: core.Membership{Name: "alice", Groups: []string{"dev"}}, Keys: []string{"github:alice"}},
		{Membership: core.Membership{Name: "bob", Groups: []string{"admin"}}, Keys: []string{"github:bob"}},
	}}

	got := Delta(vstate, declared)
	require.Len(t, got.Changes, 2)
	require.Equal(t, "bob", got.Changes[0].User, got.String())
	require.Equal(t, "alice", got.Changes[1].User, got.String())
}

// TestCompareChangesUnknownOpSortsLast regresses a plain opRank[op] lookup: a
// missing map entry silently returns the zero value, which sorted an
// operation opRank has never heard of as if it were OpUserTell (rank 0) -
// first and safest, exactly backwards from a safe default for something
// unrecognised.
func TestCompareChangesUnknownOpSortsLast(t *testing.T) {
	changes := []Change{
		{Op: core.Operation("bogus"), User: "z"},
		{Op: core.OpUserTell, User: "a"},
		{Op: core.OpUserKill, User: "a"},
	}
	slices.SortStableFunc(changes, compareChanges)

	require.Equal(
		t,
		[]core.Operation{core.OpUserTell, core.OpUserKill, core.Operation("bogus")},
		ops(&Diff{Changes: changes}),
	)
}

// applyTo mimics what the audit log does with a change, mirroring the
// normalization in core's verification: a user's groups are deduplicated, a
// secret's access list additionally gains the implicit "admin", and a key spec
// resolves to material carrying the spec as its source.
//
// It exists to check convergence (see TestDeltaConverges) without a
// repository. The real round trip belongs to the apply side once it exists.
func applyTo(t *testing.T, vstate *core.VerifiedState, c Change) {
	t.Helper()

	switch c.Op {
	case core.OpUserTell:
		recps := make(core.Recipients, 0, len(c.Keys))
		for _, spec := range c.Keys {
			recps = append(recps, newRecipient(t, core.KeySource(spec)))
		}
		vstate.Users = append(vstate.Users, core.VerifiedUser{Membership: core.Membership{Name: c.User, Groups: normalized(c.Groups)}, Recps: recps})
	case core.OpUserKill:
		vstate.Users = slices.DeleteFunc(vstate.Users, func(u core.VerifiedUser) bool {
			return u.Name == c.User
		})
	case core.OpUserChangeGroups:
		user, ok := vstate.UserExists(c.User)
		require.True(t, ok)
		user.Groups = normalized(c.Groups)
	case core.OpUserAddRecipients:
		user, ok := vstate.UserExists(c.User)
		require.True(t, ok)
		for _, spec := range c.Keys {
			user.Recps = append(user.Recps, newRecipient(t, core.KeySource(spec)))
		}
	case core.OpUserRmRecipients:
		user, ok := vstate.UserExists(c.User)
		require.True(t, ok)
		user.Recps = slices.DeleteFunc(user.Recps, func(r *core.Recipient) bool {
			return slices.Contains(c.Keys, r.String())
		})
	case core.OpSecretAdd:
		vstate.Secrets = append(vstate.Secrets, core.SecretAccess{RevealedPath: c.Path, AccessGroups: normalized(append(slices.Clone(c.Groups), "admin"))})
	case core.OpSecretRemove:
		vstate.Secrets = slices.DeleteFunc(vstate.Secrets, func(s core.SecretAccess) bool {
			return s.RevealedPath == c.Path
		})
	case core.OpSecretChangeAccess:
		secret, ok := vstate.SecretExists(c.Path)
		require.True(t, ok)
		secret.AccessGroups = normalized(append(slices.Clone(c.Groups), "admin"))
	default:
		t.Fatalf("unexpected core.Operation: %#v", c.Op)
	}

	// Appending and deleting move entries, so the lookup indexes have to be
	// rebuilt - exactly what core does after each of its own modifications.
	vstate.BuildIndexes()
}

// TestDeltaConverges is the property the whole module hinges on: applying a
// diff has to make the next one empty. A normalization that disagrees with the
// audit log's - the implicit admin group leaking into a payload, a key spec
// that never matches the recipient it produced - shows up here as a change that
// keeps being proposed forever.
func TestDeltaConverges(t *testing.T) {
	vstate := verifiedState(
		[]core.VerifiedUser{
			{Name: "alice", Groups: []string{"admin"}, Recps: core.Recipients{newRecipient(t, "github:alice")}},
			{Name: "mallory", Groups: []string{"dev"}, Recps: core.Recipients{newRecipient(t, "github:mallory")}},
		},
		[]core.SecretAccess{
			verifiedSecret("old.env", "dev"),
			verifiedSecret("db.env", "dev"),
		},
	)

	declared := &config.State{
		Users: []config.StateUser{
			{Membership: core.Membership{Name: "alice", Groups: []string{"admin", "dev"}}, Keys: []string{"github:alice"}},
			{Membership: core.Membership{Name: "bob", Groups: []string{"ops"}}, Keys: []string{"github:bob", "https://example.com/k.pub"}},
		},
		Secrets: []core.SecretAccess{
			// "admin" spelled out on one, left implicit on the other.
			declaredSecret("db.env", "admin", "ops"),
			declaredSecret("new.env", "dev"),
		},
	}

	first := Delta(vstate, declared)
	require.False(t, first.IsEmpty())

	for _, c := range first.Changes {
		applyTo(t, vstate, c)
	}

	second := Delta(vstate, declared)
	require.True(t, second.IsEmpty(), "diff did not converge:\n%s", second.String())
}

// TestDeltaDoesNotMutateVerifiedState regresses slices.Compact operating in
// place on vu.Groups: UserExists returns a pointer straight into the caller's
// VerifiedState, so compacting it without cloning first silently reordered
// the verified state's own group slice as a side effect of computing a diff -
// which Delta's own doc comment promises never happens ("touches no file,
// no network").
func TestDeltaDoesNotMutateVerifiedState(t *testing.T) {
	bob := core.VerifiedUser{
		Membership: core.Membership{Name: "bob", Groups: []string{"dev", "dev", "ops"}},
		Recps:      core.Recipients{newRecipient(t, "github:bob")},
	}
	vstate := verifiedState([]core.VerifiedUser{admin(t), bob}, nil)
	before := slices.Clone(vstate.Users[1].Groups)

	declared := &config.State{Users: []config.StateUser{
		declaredAdmin(),
		{
			Membership: core.Membership{Name: "bob", Groups: []string{"dev", "ops", "qa"}},
			Keys:       []string{"github:bob"},
		},
	}}

	Delta(vstate, declared)
	require.Equal(t, before, vstate.Users[1].Groups,
		"Delta must not mutate the verified state's group slice")
}

// TestChangeConflicts covers the guard requireLocalChanges relies on: a
// committed change must still be recognised even when a local edit to the
// same user changes its Groups or Keys set, so Equal (exact-set match) no
// longer applies to it.
func TestChangeConflicts(t *testing.T) {
	tests := []struct {
		name string
		a, b Change
		want bool
	}{
		{
			name: "identical changes conflict",
			a:    Change{Op: core.OpUserTell, User: "bob", Groups: []string{"dev"}, Keys: []string{"k1"}},
			b:    Change{Op: core.OpUserTell, User: "bob", Groups: []string{"dev"}, Keys: []string{"k1"}},
			want: true,
		},
		{
			name: "a local edit widening Groups still conflicts on the shared group",
			// Regression: a committed grant of "dev" must still be caught even
			// once a local edit also adds "ops", which used to make the exact-
			// set Equal check miss it entirely.
			a:    Change{Op: core.OpUserTell, User: "bob", Groups: []string{"dev", "ops"}, Keys: []string{"k1"}},
			b:    Change{Op: core.OpUserTell, User: "bob", Groups: []string{"dev"}, Keys: []string{"k1"}},
			want: true,
		},
		{
			name: "a local edit adding an unrelated key still conflicts on the shared one",
			a:    Change{Op: core.OpUserAddRecipients, User: "bob", Keys: []string{"attacker-key", "local-key"}},
			b:    Change{Op: core.OpUserAddRecipients, User: "bob", Keys: []string{"attacker-key"}},
			want: true,
		},
		{
			name: "disjoint groups and keys do not conflict",
			a:    Change{Op: core.OpUserTell, User: "bob", Groups: []string{"ops"}, Keys: []string{"k2"}},
			b:    Change{Op: core.OpUserTell, User: "bob", Groups: []string{"dev"}, Keys: []string{"k1"}},
			want: false,
		},
		{
			name: "different op on the same user does not conflict",
			a:    Change{Op: core.OpUserKill, User: "bob"},
			b:    Change{Op: core.OpUserTell, User: "bob", Groups: []string{"dev"}, Keys: []string{"k1"}},
			want: false,
		},
		{
			name: "different user does not conflict",
			a:    Change{Op: core.OpUserTell, User: "alice", Groups: []string{"dev"}, Keys: []string{"k1"}},
			b:    Change{Op: core.OpUserTell, User: "bob", Groups: []string{"dev"}, Keys: []string{"k1"}},
			want: false,
		},
		{
			name: "no-payload ops conflict on Op+User alone",
			a:    Change{Op: core.OpUserKill, User: "bob"},
			b:    Change{Op: core.OpUserKill, User: "bob"},
			want: true,
		},
		{
			name: "no-payload ops conflict on Op+Path alone",
			a:    Change{Op: core.OpSecretRemove, Path: "db.env"},
			b:    Change{Op: core.OpSecretRemove, Path: "db.env"},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.a.Conflicts(tc.b))
			require.Equal(t, tc.want, tc.b.Conflicts(tc.a), "Conflicts must be symmetric")
		})
	}
}

func TestChangeString(t *testing.T) {
	tests := []struct {
		change Change
		want   string
	}{
		{
			change: Change{Op: core.OpUserTell, User: "bob", Groups: []string{"dev"}, Keys: []string{"github:bob"}},
			want:   "+ user bob (groups: dev, keys: github:bob)",
		},
		{change: Change{Op: core.OpUserKill, User: "bob"}, want: "- user bob"},
		{
			change: Change{Op: core.OpUserChangeGroups, User: "bob", Groups: []string{"dev", "ops"}, Old: []string{"dev"}},
			want:   "~ user bob groups: dev -> dev, ops",
		},
		{
			change: Change{Op: core.OpSecretAdd, Path: "db.env", Groups: []string{"dev"}},
			want:   "+ secret db.env (access: dev)",
		},
		{
			change: Change{Op: core.OpSecretChangeAccess, Path: "db.env", Groups: []string{}, Old: []string{"dev"}},
			want:   "~ secret db.env access: dev -> -",
		},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			require.Equal(t, tc.want, tc.change.String())
		})
	}
}

// TestChangeJSONDistinguishesRevokedFromNotApplicable regresses omitempty on
// Groups/Old hiding a secret revoked down to admin-only (or a user left with
// no groups of its own): that must serialize as "[]", not disappear the way
// an operation Groups/Old genuinely doesn't apply to (nil) does.
func TestChangeJSONDistinguishesRevokedFromNotApplicable(t *testing.T) {
	revoked := Change{Op: core.OpSecretChangeAccess, Path: "db.env", Groups: []string{}, Old: []string{"dev"}}
	data, err := json.Marshal(revoked)
	require.NoError(t, err)
	require.JSONEq(t, `{"op":"secret.change_access","path":"db.env","groups":[],"old":["dev"]}`, string(data))

	notApplicable := Change{Op: core.OpSecretRemove, Path: "db.env"}
	data, err = json.Marshal(notApplicable)
	require.NoError(t, err)
	require.JSONEq(t, `{"op":"secret.remove","path":"db.env","groups":null,"old":null}`, string(data))
}

// normalized sorts and deduplicates a group set the way core's verification
// stores one, so applyTo produces states the audit log could actually hold.
func normalized(s []string) []string {
	return slices.Compact(slices.Sorted(slices.Values(s)))
}

// nilIfEmpty lets a table entry leave `want` unset for "no changes".
func nilIfEmpty(changes []Change) []Change {
	if len(changes) == 0 {
		return nil
	}

	return changes
}

// ptr is shorthand for taking the address of a freshly built value.
func ptr[T any](v T) *T { return &v }
