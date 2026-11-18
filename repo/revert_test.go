package repo

import (
	"encoding/json"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/core"
)

type revertUser struct {
	name   string
	groups []string
	keys   []*core.Recipient
}

type revertSecret struct {
	path   string
	groups []string
}

type revertFixture struct {
	users   []revertUser
	secrets []revertSecret
}

func testRecipient(t *testing.T) *core.Recipient {
	t.Helper()

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	recp, err := core.ParseRecipient(id.Recipient().String(), core.NewNonInteractivePluginUI())
	require.NoError(t, err)
	return recp
}

func (f revertFixture) state() *core.VerifiedState {
	s := &core.VerifiedState{}
	for _, u := range f.users {
		s.Users = append(s.Users, core.VerifiedUser{
			Membership: core.Membership{Name: u.name, Groups: u.groups},
			Recps:      core.Recipients(u.keys),
		})
	}

	for _, sec := range f.secrets {
		s.Secrets = append(s.Secrets, core.SecretAccess{
			RevealedPath: sec.path,
			AccessGroups: append([]string{"admin"}, sec.groups...),
		})
	}

	return s
}

func revertEntry[T core.AuditDetail](t *testing.T, op core.Operation, detail *T) core.AuditEntrySigned {
	t.Helper()

	raw, err := json.Marshal(detail)
	require.NoError(t, err)
	return core.AuditEntrySigned{AuditEntry: core.AuditEntry{Operation: op, Detail: raw}}
}

func TestPlanRevertSteps(t *testing.T) {
	k1, k2, k3 := testRecipient(t), testRecipient(t), testRecipient(t)

	admin := revertUser{"admin", []string{"admin"}, []*core.Recipient{k1}}
	bob := func(groups ...string) revertUser {
		return revertUser{"bob", groups, []*core.Recipient{k2}}
	}

	tests := []struct {
		name                string
		before, after, head revertFixture
		delta               []core.AuditEntrySigned
		steps               []RevertStep
		skipped             []string
	}{
		{
			name:   "tell is undone by a kill",
			before: revertFixture{users: []revertUser{admin}},
			after:  revertFixture{users: []revertUser{admin, bob("dev")}},
			head:   revertFixture{users: []revertUser{admin, bob("dev")}},
			steps:  []RevertStep{{Op: core.OpUserKill, User: "bob"}},
		},
		{
			name:    "tell of a user killed since is skipped",
			before:  revertFixture{users: []revertUser{admin}},
			after:   revertFixture{users: []revertUser{admin, bob("dev")}},
			head:    revertFixture{users: []revertUser{admin}},
			skipped: []string{"user.tell bob"},
		},
		{
			name:    "the reverting user is not killed",
			before:  revertFixture{users: []revertUser{bob("admin")}},
			after:   revertFixture{users: []revertUser{bob("admin"), admin}},
			head:    revertFixture{users: []revertUser{bob("admin"), admin}},
			skipped: []string{"user.tell admin"},
		},
		{
			name:   "kill is undone by a tell with the recorded keys",
			before: revertFixture{users: []revertUser{admin, bob("dev")}},
			after:  revertFixture{users: []revertUser{admin}},
			head:   revertFixture{users: []revertUser{admin}},
			steps: []RevertStep{{
				Op: core.OpUserTell, User: "bob", Groups: []string{"dev"}, Keys: []string{k2.String()},
			}},
		},
		{
			name:    "kill of a name that exists again is skipped",
			before:  revertFixture{users: []revertUser{admin, bob("dev")}},
			after:   revertFixture{users: []revertUser{admin}},
			head:    revertFixture{users: []revertUser{admin, bob("ops")}},
			skipped: []string{"user.kill bob"},
		},
		{
			name:   "group change keeps what HEAD added since",
			before: revertFixture{users: []revertUser{admin, bob("dev")}},
			after:  revertFixture{users: []revertUser{admin, bob("dev", "ops")}},
			head:   revertFixture{users: []revertUser{admin, bob("dev", "ops", "qa")}},
			steps:  []RevertStep{{Op: core.OpUserChangeGroups, User: "bob", Groups: []string{"dev", "qa"}}},
		},
		{
			name:   "group change already undone at HEAD needs nothing",
			before: revertFixture{users: []revertUser{admin, bob("dev")}},
			after:  revertFixture{users: []revertUser{admin, bob("dev", "ops")}},
			head:   revertFixture{users: []revertUser{admin, bob("dev")}},
		},
		{
			name:   "recipients swap back",
			before: revertFixture{users: []revertUser{admin, {"bob", []string{"dev"}, []*core.Recipient{k2}}}},
			after:  revertFixture{users: []revertUser{admin, {"bob", []string{"dev"}, []*core.Recipient{k3}}}},
			head:   revertFixture{users: []revertUser{admin, {"bob", []string{"dev"}, []*core.Recipient{k3}}}},
			steps: []RevertStep{
				{Op: core.OpUserAddRecipients, User: "bob", Keys: []string{k2.String()}},
				{Op: core.OpUserRmRecipients, User: "bob", Keys: []string{k3.String()}},
			},
		},
		{
			name:   "secret add is undone by a remove",
			before: revertFixture{users: []revertUser{admin}},
			after:  revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"s", []string{"dev"}}}},
			head:   revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"s", []string{"dev"}}}},
			steps:  []RevertStep{{Op: core.OpSecretRemove, Path: "s"}},
		},
		{
			name:   "secret remove is undone by an add with the old access list",
			before: revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"s", []string{"dev"}}}},
			after:  revertFixture{users: []revertUser{admin}},
			head:   revertFixture{users: []revertUser{admin}},
			steps:  []RevertStep{{Op: core.OpSecretAdd, Path: "s", Groups: []string{"dev"}}},
		},
		{
			name:   "access change keeps what HEAD changed since",
			before: revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"s", []string{"dev"}}}},
			after:  revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"s", nil}}},
			head:   revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"s", []string{"ops"}}}},
			steps:  []RevertStep{{Op: core.OpSecretChangeAccess, Path: "s", Groups: []string{"dev", "ops"}}},
		},
		{
			name:   "rename goes back first, then the rest uses the old name",
			before: revertFixture{users: []revertUser{admin, bob("dev")}},
			after:  revertFixture{users: []revertUser{admin, {"robert", []string{"dev", "ops"}, []*core.Recipient{k2}}}},
			head:   revertFixture{users: []revertUser{admin, {"robert", []string{"dev", "ops"}, []*core.Recipient{k2}}}},
			delta: []core.AuditEntrySigned{
				revertEntry(t, core.OpUserRename, &core.DetailUserRename{OldName: "bob", NewName: "rob"}),
				revertEntry(t, core.OpUserRename, &core.DetailUserRename{OldName: "rob", NewName: "robert"}),
			},
			steps: []RevertStep{
				{Op: core.OpUserRename, User: "robert", To: "bob"},
				{Op: core.OpUserChangeGroups, User: "bob", Groups: []string{"dev"}},
			},
		},
		{
			name:   "rename of a user renamed again since is skipped",
			before: revertFixture{users: []revertUser{admin, bob("dev")}},
			after:  revertFixture{users: []revertUser{admin, {"robert", []string{"dev"}, []*core.Recipient{k2}}}},
			head:   revertFixture{users: []revertUser{admin, {"bobby", []string{"dev"}, []*core.Recipient{k2}}}},
			delta: []core.AuditEntrySigned{
				revertEntry(t, core.OpUserRename, &core.DetailUserRename{OldName: "bob", NewName: "robert"}),
			},
			skipped: []string{"user.rename robert"},
		},
		{
			name:   "move goes back",
			before: revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"a", nil}}},
			after:  revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"b", nil}}},
			head:   revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"b", nil}}},
			delta: []core.AuditEntrySigned{
				revertEntry(t, core.OpSecretMove, &core.DetailSecretMove{OldRevealedPath: "a", NewRevealedPath: "b"}),
			},
			steps: []RevertStep{{Op: core.OpSecretMove, Path: "b", To: "a"}},
		},
		{
			name:   "move onto a path taken again is skipped",
			before: revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"a", nil}}},
			after:  revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"b", nil}}},
			head:   revertFixture{users: []revertUser{admin}, secrets: []revertSecret{{"a", nil}, {"b", nil}}},
			delta: []core.AuditEntrySigned{
				revertEntry(t, core.OpSecretMove, &core.DetailSecretMove{OldRevealedPath: "a", NewRevealedPath: "b"}),
			},
			skipped: []string{"secret.move b"},
		},
		{
			name:   "signing key rotation is skipped",
			before: revertFixture{users: []revertUser{admin}},
			after:  revertFixture{users: []revertUser{admin}},
			head:   revertFixture{users: []revertUser{admin}},
			delta: []core.AuditEntrySigned{
				revertEntry(t, core.OpUserRegenerateSignKey, &core.DetailUserRegenerateSignKey{User: "admin"}),
			},
			skipped: []string{"user.regenerate_sign_key admin"},
		},
		{
			name:   "promotion runs before the demotion it makes possible",
			before: revertFixture{users: []revertUser{admin, bob("admin")}},
			after:  revertFixture{users: []revertUser{{"admin", []string{"dev"}, []*core.Recipient{k1}}, bob("dev")}},
			head:   revertFixture{users: []revertUser{{"admin", []string{"dev"}, []*core.Recipient{k1}}, bob("dev")}},
			steps: []RevertStep{
				{Op: core.OpUserChangeGroups, User: "admin", Groups: []string{"admin"}},
				{Op: core.OpUserChangeGroups, User: "bob", Groups: []string{"admin"}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan, _, err := planRevertSteps(tc.before.state(), tc.after.state(), tc.head.state(), tc.delta, "admin")
			require.NoError(t, err)

			if tc.steps == nil {
				tc.steps = []RevertStep{}
			}
			require.Equal(t, tc.steps, plan.Steps)

			var skipped []string
			for _, s := range plan.Skipped {
				skipped = append(skipped, string(s.Op)+" "+s.Target)
			}
			require.Equal(t, tc.skipped, skipped)
		})
	}
}

func TestRevertDelta(t *testing.T) {
	entry := func(op core.Operation, sig string) core.AuditEntrySigned {
		return core.AuditEntrySigned{AuditEntry: core.AuditEntry{Operation: op}, Signature: sig}
	}

	base := []core.AuditEntrySigned{entry(core.OpInit, "a"), entry(core.OpUserTell, "b")}

	tests := []struct {
		name   string
		after  []core.AuditEntrySigned
		refuse string
		delta  int
	}{
		{"appended", append(base[:2:2], entry(core.OpUserKill, "c")), "", 1},
		{"unchanged", base, "", 0},
		{"shortened", base[:1], "shortened", 0},
		{"rewritten", []core.AuditEntrySigned{base[0], entry(core.OpUserTell, "x")}, "rewrote", 0},
		{"merge", append(base[:2:2], entry(core.OpMerge, "c")), "merge", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			delta, err := revertDelta(&core.AuditLog{Entries: base}, &core.AuditLog{Entries: tc.after})
			if tc.refuse != "" {
				var refused *RefusedRevertError
				require.ErrorAs(t, err, &refused)
				require.Contains(t, refused.Reason, tc.refuse)
				return
			}

			require.NoError(t, err)
			require.Len(t, delta, tc.delta)
		})
	}
}

func TestThreeWay(t *testing.T) {
	tests := []struct {
		name                string
		base, current, undo []string
		want                []string
	}{
		{"takes back an addition", []string{"a", "b"}, []string{"a", "b"}, []string{"a"}, []string{"a"}},
		{"takes back a removal", []string{"a"}, []string{"a"}, []string{"a", "b"}, []string{"a", "b"}},
		{"keeps later additions", []string{"a", "b"}, []string{"a", "b", "c"}, []string{"a"}, []string{"a", "c"}},
		{"keeps later removals", []string{"a", "b"}, []string{"b"}, []string{"a"}, []string{}},
		{"nothing to take back", []string{"a"}, []string{"a", "c"}, []string{"a"}, []string{"a", "c"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, threeWay(tc.base, tc.current, tc.undo))
		})
	}
}
