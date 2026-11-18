package repo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo/util"
)

// RevertStep is one inverse operation a revert records in the audit log. Only
// the fields its Op needs are set.
type RevertStep struct {
	Op core.Operation `json:"op"`

	// User and Path name the user or secret the step acts on, as it is called at
	// HEAD when the step runs. To is the new name of a rename or move.
	User string `json:"user,omitempty"`
	Path string `json:"path,omitempty"`
	To   string `json:"to,omitempty"`

	// Groups is the target set: a user's groups, or a secret's access list
	// without the implicit "admin".
	Groups []string `json:"groups,omitempty"`

	// Keys is recorded key material, never a spec that would be resolved again.
	Keys []string `json:"keys,omitempty"`
}

// RevertSkip is a part of the reverted commit that is left as it is, and why.
type RevertSkip struct {
	Op     core.Operation `json:"op"`
	Target string         `json:"target"`
	Reason string         `json:"reason"`
}

// RevertContent is the plaintext a secret gets back. Conflicts counts the
// conflict hunks the three-way merge left in Data.
type RevertContent struct {
	Path      string `json:"path"`
	Conflicts int    `json:"conflicts"`

	// headPath is where the secret lives at HEAD, before the steps move it.
	headPath string
	data     []byte
}

// RevertPlan is everything a revert would do, worked out without writing
// anything.
type RevertPlan struct {
	Steps   []RevertStep    `json:"steps"`
	Content []RevertContent `json:"content"`
	Skipped []RevertSkip    `json:"skipped"`
}

// RevertResult names the secrets left with conflict markers.
type RevertResult struct {
	Conflicted []string `json:"conflicted"`
}

// RefusedRevertError reports a commit that cannot be reverted at all.
type RefusedRevertError struct {
	Reason string
}

// renames maps the names of the reverted commit's parent - the names a revert
// goes back to - onto the commit and onto HEAD. A name that is not in a map is
// unchanged; an empty value in head means the user or secret is gone at HEAD,
// or its rename is not undone, so nothing more is done for it.
type renames struct {
	afterUsers, afterSecrets map[string]string
	headUsers, headSecrets   map[string]string
}

func (e *RefusedRevertError) Error() string {
	return "cannot revert: " + e.Reason
}

// IsEmpty reports whether the plan would change nothing.
func (p *RevertPlan) IsEmpty() bool {
	return len(p.Steps) == 0 && len(p.Content) == 0
}

// String renders a step as a single line, in the style of diff.Change.
func (s RevertStep) String() string {
	switch s.Op {
	case core.OpUserTell:
		return fmt.Sprintf("+ user %s (groups: %s)", s.User, joinOrDash(s.Groups))
	case core.OpUserKill:
		return fmt.Sprintf("- user %s", s.User)
	case core.OpUserRename:
		return fmt.Sprintf("~ user %s -> %s", s.User, s.To)
	case core.OpUserChangeGroups:
		return fmt.Sprintf("~ user %s groups: %s", s.User, joinOrDash(s.Groups))
	case core.OpUserAddRecipients:
		return fmt.Sprintf("+ keys of user %s: %d", s.User, len(s.Keys))
	case core.OpUserRmRecipients:
		return fmt.Sprintf("- keys of user %s: %d", s.User, len(s.Keys))
	case core.OpSecretAdd:
		return fmt.Sprintf("+ secret %s (access: %s)", s.Path, joinOrDash(s.Groups))
	case core.OpSecretRemove:
		return fmt.Sprintf("- secret %s", s.Path)
	case core.OpSecretMove:
		return fmt.Sprintf("~ secret %s -> %s", s.Path, s.To)
	case core.OpSecretChangeAccess:
		return fmt.Sprintf("~ secret %s access: %s", s.Path, joinOrDash(s.Groups))
	default:
		return fmt.Sprintf("? %s", s.Op)
	}
}

// PlanRevert works out how to undo the commit whose sesam state is `after`,
// with `before` being the state of its parent. Both must have been loaded and
// verified by the caller. The inverse is rebased onto the live state: whatever
// HEAD changed since is kept, and parts that no longer apply are skipped.
func (r *Repo) PlanRevert(ctx context.Context, before, after *Repo) (*RevertPlan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() || before.isClosed() || after.isClosed() {
		return nil, ErrClosed
	}

	delta, err := revertDelta(before.auditLog, after.auditLog)
	if err != nil {
		return nil, err
	}

	plan, rn, err := planRevertSteps(before.vstate, after.vstate, r.vstate, delta, r.whoami)
	if err != nil {
		return nil, err
	}

	if err := r.planRevertContent(ctx, before, after, plan, rn); err != nil {
		return nil, err
	}

	return plan, nil
}

// ApplyRevert carries out plan in one stage: the steps, the restored plaintext
// and a seal. Plaintext the merge left conflicted is written only after the
// stage committed, so it is never sealed.
func (r *Repo) ApplyRevert(ctx context.Context, plan *RevertPlan) (*RevertResult, error) {
	res := &RevertResult{}

	var clean, conflicted []RevertContent
	for _, c := range plan.Content {
		if c.Conflicts > 0 {
			conflicted = append(conflicted, c)
			continue
		}

		clean = append(clean, c)
	}

	// The stage rolls back what it created itself; plaintext it overwrote is put
	// back from here.
	backups := map[string][]byte{}
	restore := func() {
		for p, data := range backups {
			if data == nil {
				_ = r.root.Remove(p)
				continue
			}

			_ = writeRevealedFile(r.root, p, data)
		}
	}

	backup := func(p string) error {
		if _, ok := backups[p]; ok {
			return nil
		}

		data, err := r.root.ReadFile(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			backups[p] = nil
		case err != nil:
			return fmt.Errorf("back up %s: %w", p, err)
		default:
			backups[p] = data
		}

		return nil
	}

	err := r.Update(func(s *Stage) error {
		// A secret that comes back needs its plaintext before it can be added.
		for _, c := range clean {
			if _, exists := s.vstate.SecretExists(c.headPath); exists {
				continue
			}

			if err := backup(c.Path); err != nil {
				return err
			}

			if err := writeRevealedFile(r.root, c.Path, c.data); err != nil {
				return err
			}
		}

		for _, step := range plan.Steps {
			if err := s.applyRevertStep(ctx, step); err != nil {
				return fmt.Errorf("revert step %q: %w", step, err)
			}
		}

		sealPaths := make([]string, 0, len(clean))
		for _, c := range clean {
			if err := backup(c.Path); err != nil {
				return err
			}

			if err := writeRevealedFile(r.root, c.Path, c.data); err != nil {
				return err
			}

			sealPaths = append(sealPaths, c.Path)
		}

		// The restored plaintext matches an older object, which a plain seal
		// would take for stale and skip - so it is named explicitly.
		_, err := s.Seal(ctx, SealOpts{Paths: sealPaths})
		return err
	})
	if err != nil {
		restore()
		return nil, err
	}

	for _, c := range conflicted {
		if err := writeRevealedFile(r.root, c.Path, c.data); err != nil {
			return nil, err
		}

		res.Conflicted = append(res.Conflicted, c.Path)
	}

	return res, nil
}

// applyRevertStep runs one step through the same stage operations the
// commands use, so config and audit log change together.
func (s *Stage) applyRevertStep(ctx context.Context, step RevertStep) error {
	switch step.Op {
	case core.OpUserTell:
		return s.UserTell(ctx, step.User, step.Keys, step.Groups, false)
	case core.OpUserKill:
		return s.UserKill(step.User)
	case core.OpUserRename:
		return s.UserRename(step.User, step.To)
	case core.OpUserChangeGroups:
		return s.UserChangeGroups(step.User, step.Groups, false)
	case core.OpUserAddRecipients:
		return s.UserAddRecipient(ctx, step.User, step.Keys)
	case core.OpUserRmRecipients:
		return s.UserRmRecipient(ctx, step.User, step.Keys)
	case core.OpSecretAdd:
		return s.SecretAdd(ctx, []string{step.Path}, step.Groups, false, false)
	case core.OpSecretRemove:
		return s.SecretRemove([]string{step.Path})
	case core.OpSecretMove:
		return s.SecretMove(step.Path, step.To, false)
	case core.OpSecretChangeAccess:
		return s.secretChangeAccess(step.Path, step.Groups)
	default:
		return fmt.Errorf("unexpected operation %q", step.Op)
	}
}

// secretChangeAccess sets a secret's access list, an empty one meaning
// admin-only - which SecretAdd would read as "no change".
func (s *Stage) secretChangeAccess(path string, groups []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.secret.SecretChangeGroups(path, groups); err != nil {
		return err
	}

	cfg, err := s.cfg()
	if err != nil {
		return err
	}

	return cfg.SecretChangeGroups(path, groups)
}

// planRevertContent decides which secrets get their plaintext back: those the
// reverted commit changed, merged onto what HEAD holds now, and those it
// removed, which come back as they were.
func (r *Repo) planRevertContent(ctx context.Context, before, after *Repo, plan *RevertPlan, rn *renames) error {
	restored := map[string]bool{}
	for _, step := range plan.Steps {
		if step.Op == core.OpSecretAdd {
			restored[step.Path] = true
		}
	}

	for _, bs := range before.vstate.Secrets {
		p := bs.RevealedPath

		if restored[p] {
			if !canReveal(before, p) {
				plan.dropSecretAdd(p, "you cannot read it, so it cannot come back")
				continue
			}

			data, err := revealToBuf(before, p)
			if err != nil {
				return err
			}

			// A file left at the path is only taken over if it holds the content.
			if onDisk, err := r.root.ReadFile(p); err == nil && !bytes.Equal(onDisk, data) {
				plan.dropSecretAdd(p, "a different file is in the way at "+p)
				continue
			}

			plan.Content = append(plan.Content, RevertContent{Path: p, headPath: p, data: data})
			continue
		}

		afterPath := rn.afterSecret(p)
		if _, exists := after.vstate.SecretExists(afterPath); !exists {
			continue
		}

		changed, err := objectChanged(before, after, p, afterPath)
		if err != nil {
			return err
		}
		if !changed {
			continue
		}

		headPath := rn.headSecretPath(r.vstate, p)
		if headPath == "" {
			plan.skip(core.OpSeal, p, "removed since, its content stays gone")
			continue
		}

		if !canReveal(before, p) || !canReveal(after, afterPath) || !canReveal(r, headPath) {
			plan.skip(core.OpSeal, p, "you cannot read it, its content stays as it is")
			continue
		}

		theirs, err := revealToBuf(before, p)
		if err != nil {
			return err
		}

		base, err := revealToBuf(after, afterPath)
		if err != nil {
			return err
		}

		// The commit only re-encrypted it, e.g. for a new recipient.
		if bytes.Equal(theirs, base) {
			continue
		}

		ours, err := revealToBuf(r, headPath)
		if err != nil {
			return err
		}

		merged, conflicts, err := r.mergeRevertContent(ctx, p, ours, base, theirs)
		if errors.Is(err, errBinaryMerge) {
			plan.skip(core.OpSeal, p, "binary content changed since, cannot merge it back")
			continue
		}
		if err != nil {
			return err
		}

		if bytes.Equal(merged, ours) {
			continue
		}

		plan.Content = append(plan.Content, RevertContent{
			Path:      p,
			Conflicts: conflicts,
			headPath:  headPath,
			data:      merged,
		})
	}

	return nil
}

// mergeRevertContent takes back the change base->theirs... in reverse: base is
// the content the commit wrote, theirs what it replaced, ours what HEAD holds.
func (r *Repo) mergeRevertContent(ctx context.Context, path string, ours, base, theirs []byte) ([]byte, int, error) {
	switch {
	case bytes.Equal(ours, base):
		return theirs, 0, nil
	case bytes.Equal(ours, theirs):
		return ours, 0, nil
	}

	var (
		abs [3]string
		tmp []string
	)

	defer func() {
		for _, p := range tmp {
			_ = r.root.Remove(p)
		}
	}()

	for i, side := range []struct {
		tag  string
		data []byte
	}{{"ours", ours}, {"origin", base}, {"theirs", theirs}} {
		rel, err := writeSecretTmpBuf(r.root, bytes.NewBuffer(side.data), path, "revert-"+side.tag)
		if rel != "" {
			tmp = append(tmp, rel)
		}
		if err != nil {
			return nil, 0, err
		}

		abs[i] = filepath.Join(r.root.Name(), rel)
	}

	merged, conflicts, err := runGitMerge(ctx, path, abs[0], abs[2], abs[1], core.ConflictMarkerMin)
	if err != nil {
		return nil, 0, err
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(merged); err != nil {
		return nil, 0, err
	}

	return buf.Bytes(), conflicts, nil
}

func (p *RevertPlan) skip(op core.Operation, target, reason string) {
	p.Skipped = append(p.Skipped, RevertSkip{Op: op, Target: target, Reason: reason})
}

// dropSecretAdd takes back the step that would restore the secret at path and
// records why. The skip names the removal by the commit it would have undone.
func (p *RevertPlan) dropSecretAdd(path, reason string) {
	p.Steps = slices.DeleteFunc(p.Steps, func(s RevertStep) bool {
		return s.Op == core.OpSecretAdd && s.Path == path
	})

	p.skip(core.OpSecretRemove, path, reason)
}

// revertDelta returns the entries the reverted commit appended to its parent's
// log, refusing a commit whose log is not a plain extension of its parent's.
func revertDelta(before, after *core.AuditLog) ([]core.AuditEntrySigned, error) {
	if len(before.Entries) > len(after.Entries) {
		return nil, &RefusedRevertError{Reason: "the commit shortened the audit log"}
	}

	for i := range before.Entries {
		if before.Entries[i].Hash() != after.Entries[i].Hash() {
			return nil, &RefusedRevertError{
				Reason: fmt.Sprintf("the commit rewrote the audit log at seq_id %d", before.Entries[i].SeqID),
			}
		}
	}

	delta := after.Entries[len(before.Entries):]
	for i := range delta {
		switch delta[i].Operation {
		case core.OpInit:
			return nil, &RefusedRevertError{Reason: "the commit initialized the repository"}
		case core.OpMerge:
			return nil, &RefusedRevertError{Reason: "the commit holds an audit log merge; revert the changes it brought in instead"}
		}
	}

	return delta, nil
}

// planRevertSteps computes the structural inverse of delta, which took the
// state from before to after, rebased onto head. whoami is the reverting user,
// who is never killed by their own revert.
func planRevertSteps(before, after, head *core.VerifiedState, delta []core.AuditEntrySigned, whoami string) (*RevertPlan, *renames, error) {
	plan := &RevertPlan{Steps: []RevertStep{}, Content: []RevertContent{}, Skipped: []RevertSkip{}}

	userMoves, secretMoves, err := collectRenames(delta, plan)
	if err != nil {
		return nil, nil, err
	}

	rn := &renames{
		afterUsers:   userMoves,
		afterSecrets: secretMoves,
		headUsers:    map[string]string{},
		headSecrets:  map[string]string{},
	}

	userExists := func(n string) bool { _, ok := head.UserExists(n); return ok }
	secretExists := func(p string) bool { _, ok := head.SecretExists(p); return ok }

	// Renames run first, so every later step can use the parent's name.
	plan.Steps = append(plan.Steps, undoRenames(plan, core.OpUserRename, userMoves, rn.headUsers, userExists)...)
	plan.Steps = append(plan.Steps, undoRenames(plan, core.OpSecretMove, secretMoves, rn.headSecrets, secretExists)...)

	var steps []RevertStep

	for i := range before.Users {
		bu := &before.Users[i]
		au, inAfter := after.UserExists(rn.afterUser(bu.Name))
		hu, inHead := rn.headUser(head, bu.Name)

		if !inAfter {
			// Killed by the commit: tell them again, with the recorded keys.
			if inHead {
				plan.skip(core.OpUserKill, bu.Name, "a user of that name exists again")
				continue
			}

			steps = append(steps, RevertStep{
				Op:     core.OpUserTell,
				User:   bu.Name,
				Groups: slices.Clone(bu.Groups),
				Keys:   bu.Recps.Strings(),
			})
			continue
		}

		changed := !stringSetEqual(bu.Groups, au.Groups) || !stringSetEqual(bu.Recps.Strings(), au.Recps.Strings())
		if !inHead {
			if changed {
				plan.skip(core.OpUserChangeGroups, bu.Name, "removed since")
			}
			continue
		}

		if groups := threeWay(au.Groups, hu.Groups, bu.Groups); !stringSetEqual(groups, hu.Groups) {
			steps = append(steps, RevertStep{Op: core.OpUserChangeGroups, User: bu.Name, Groups: groups})
		}

		if add := setMinus(setMinus(bu.Recps.Strings(), au.Recps.Strings()), hu.Recps.Strings()); len(add) > 0 {
			steps = append(steps, RevertStep{Op: core.OpUserAddRecipients, User: bu.Name, Keys: add})
		}

		if rm := setIntersect(setMinus(au.Recps.Strings(), bu.Recps.Strings()), hu.Recps.Strings()); len(rm) > 0 {
			steps = append(steps, RevertStep{Op: core.OpUserRmRecipients, User: bu.Name, Keys: rm})
		}
	}

	known := knownAfter(before.Users, userMoves, func(u core.VerifiedUser) string { return u.Name })
	for i := range after.Users {
		au := &after.Users[i]
		if known[au.Name] {
			continue
		}

		// Told by the commit: kill them again.
		switch {
		case !userExists(au.Name):
			plan.skip(core.OpUserTell, au.Name, "already removed since")
		case au.Name == whoami:
			plan.skip(core.OpUserTell, au.Name, "that is you; you cannot remove yourself")
		default:
			steps = append(steps, RevertStep{Op: core.OpUserKill, User: au.Name})
		}
	}

	for i := range before.Secrets {
		bs := &before.Secrets[i]
		as, inAfter := after.SecretExists(rn.afterSecret(bs.RevealedPath))
		hs, inHead := rn.headSecret(head, bs.RevealedPath)

		if !inAfter {
			// Removed by the commit: add it back with its old access list.
			if inHead {
				plan.skip(core.OpSecretRemove, bs.RevealedPath, "a secret at that path exists again")
				continue
			}

			steps = append(steps, RevertStep{Op: core.OpSecretAdd, Path: bs.RevealedPath, Groups: bs.DeclaredGroups()})
			continue
		}

		if !inHead {
			continue
		}

		groups := threeWay(as.DeclaredGroups(), hs.DeclaredGroups(), bs.DeclaredGroups())
		if !stringSetEqual(groups, hs.DeclaredGroups()) {
			steps = append(steps, RevertStep{Op: core.OpSecretChangeAccess, Path: bs.RevealedPath, Groups: groups})
		}
	}

	known = knownAfter(before.Secrets, secretMoves, func(s core.SecretAccess) string { return s.RevealedPath })
	for i := range after.Secrets {
		as := &after.Secrets[i]
		if known[as.RevealedPath] {
			continue
		}

		// Added by the commit: remove it again.
		if !secretExists(as.RevealedPath) {
			plan.skip(core.OpSecretAdd, as.RevealedPath, "already removed since")
			continue
		}

		steps = append(steps, RevertStep{Op: core.OpSecretRemove, Path: as.RevealedPath})
	}

	slices.SortStableFunc(steps, compareRevertSteps)
	plan.Steps = append(plan.Steps, steps...)

	return plan, rn, nil
}

// collectRenames folds the renames and moves of delta into one mapping each,
// from the parent's name to the commit's, so a chain a->b->c reads a->c. It
// also records the signing key rotations, which are never undone.
func collectRenames(delta []core.AuditEntrySigned, plan *RevertPlan) (users, secrets map[string]string, err error) {
	users, secrets = map[string]string{}, map[string]string{}

	follow := func(m map[string]string, from, to string) {
		for origin, cur := range m {
			if cur == from {
				m[origin] = to
				return
			}
		}

		m[from] = to
	}

	for i := range delta {
		e := &delta[i]

		switch e.Operation {
		case core.OpUserRename:
			var d core.DetailUserRename
			if err := json.Unmarshal(e.Detail, &d); err != nil {
				return nil, nil, fmt.Errorf("seq_id %d: %w", e.SeqID, err)
			}
			follow(users, d.OldName, d.NewName)

		case core.OpSecretMove:
			var d core.DetailSecretMove
			if err := json.Unmarshal(e.Detail, &d); err != nil {
				return nil, nil, fmt.Errorf("seq_id %d: %w", e.SeqID, err)
			}
			follow(secrets, d.OldRevealedPath, d.NewRevealedPath)

		case core.OpUserRegenerateSignKey:
			var d core.DetailUserRegenerateSignKey
			if err := json.Unmarshal(e.Detail, &d); err != nil {
				return nil, nil, fmt.Errorf("seq_id %d: %w", e.SeqID, err)
			}
			plan.skip(e.Operation, d.User, "a signing key is never rolled back")
		}
	}

	for from, to := range users {
		if from == to {
			delete(users, from)
		}
	}
	for from, to := range secrets {
		if from == to {
			delete(secrets, from)
		}
	}

	return users, secrets, nil
}

// undoRenames plans a rename back for every entry of moves (parent name ->
// commit name) and records in head what each name is called at HEAD before
// the steps run.
func undoRenames(plan *RevertPlan, op core.Operation, moves, head map[string]string, exists func(string) bool) []RevertStep {
	var steps []RevertStep
	for _, from := range slices.Sorted(maps.Keys(moves)) {
		to := moves[from]

		switch {
		case !exists(to):
			plan.skip(op, to, "renamed or removed since")
			head[from] = ""
		case exists(from):
			plan.skip(op, to, from+" is taken again")
			head[from] = ""
		default:
			if op == core.OpUserRename {
				steps = append(steps, RevertStep{Op: op, User: to, To: from})
			} else {
				steps = append(steps, RevertStep{Op: op, Path: to, To: from})
			}
			head[from] = to
		}
	}

	return steps
}

// knownAfter is the set of names in the commit that its parent already had,
// possibly under another name. Everything else was created by the commit.
func knownAfter[T any](before []T, moves map[string]string, name func(T) string) map[string]bool {
	known := make(map[string]bool, len(before))
	for _, x := range before {
		n := name(x)
		if to, ok := moves[n]; ok {
			n = to
		}

		known[n] = true
	}

	return known
}

func (rn *renames) afterUser(name string) string {
	if to, ok := rn.afterUsers[name]; ok {
		return to
	}

	return name
}

func (rn *renames) afterSecret(p string) string {
	if to, ok := rn.afterSecrets[p]; ok {
		return to
	}

	return p
}

// headUser finds the user the parent called name at HEAD.
func (rn *renames) headUser(head *core.VerifiedState, name string) (*core.VerifiedUser, bool) {
	cur, ok := rn.headUsers[name]
	if !ok {
		cur = name
	}

	if cur == "" {
		return nil, false
	}

	return head.UserExists(cur)
}

// headSecretPath is where the secret the parent had at p lives at HEAD, before
// the steps run. Empty when it is not there.
func (rn *renames) headSecretPath(head *core.VerifiedState, p string) string {
	cur, ok := rn.headSecrets[p]
	if !ok {
		cur = p
	}

	if _, exists := head.SecretExists(cur); cur == "" || !exists {
		return ""
	}

	return cur
}

func (rn *renames) headSecret(head *core.VerifiedState, p string) (*core.SecretAccess, bool) {
	cur := rn.headSecretPath(head, p)
	if cur == "" {
		return nil, false
	}

	return head.SecretExists(cur)
}

// revertOpRank orders steps so no intermediate state is rejected, the same way
// diff.opRank does: additions before removals, renames before everything.
var revertOpRank = map[core.Operation]int{
	core.OpUserRename:         0,
	core.OpSecretMove:         0,
	core.OpUserTell:           1,
	core.OpUserAddRecipients:  2,
	core.OpUserChangeGroups:   3,
	core.OpSecretAdd:          4,
	core.OpSecretChangeAccess: 5,
	core.OpSecretRemove:       6,
	core.OpUserRmRecipients:   7,
	core.OpUserKill:           8,
}

func compareRevertSteps(a, b RevertStep) int {
	if c := revertOpRank[a.Op] - revertOpRank[b.Op]; c != 0 {
		return c
	}

	// Promotions before demotions: the last admin may not go first.
	if a.Op == core.OpUserChangeGroups {
		aa, ba := slices.Contains(a.Groups, "admin"), slices.Contains(b.Groups, "admin")
		if aa != ba {
			if aa {
				return -1
			}

			return 1
		}
	}

	if c := strings.Compare(a.User, b.User); c != 0 {
		return c
	}

	return strings.Compare(a.Path, b.Path)
}

// threeWay takes back the change base->undo from current: what the commit
// added (in base, not in undo) is dropped, what it dropped is added again, and
// everything HEAD changed since is kept.
func threeWay(base, current, undo []string) []string {
	out := setMinus(current, setMinus(base, undo))
	return util.SortedSet(append(out, setMinus(undo, base)...))
}

func setMinus(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if !slices.Contains(b, x) && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}

	return out
}

func setIntersect(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if slices.Contains(b, x) && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}

	return out
}

func stringSetEqual(a, b []string) bool {
	return slices.Equal(util.SortedSet(a), util.SortedSet(b))
}

func joinOrDash(s []string) string {
	if len(s) == 0 {
		return "-"
	}

	return strings.Join(s, ", ")
}

// objectChanged reports whether the commit replaced the object, comparing the
// bytes git stored on both sides.
func objectChanged(before, after *Repo, beforePath, afterPath string) (bool, error) {
	b, err := before.root.ReadFile(core.ObjectPath(beforePath))
	if err != nil {
		return false, fmt.Errorf("read %s before the commit: %w", beforePath, err)
	}

	a, err := after.root.ReadFile(core.ObjectPath(afterPath))
	if err != nil {
		return false, fmt.Errorf("read %s at the commit: %w", afterPath, err)
	}

	return !bytes.Equal(a, b), nil
}

func canReveal(r *Repo, p string) bool {
	s, ok := r.vstate.SecretExists(p)
	return ok && r.vstate.UserHasAccess(r.whoami, s.AccessGroups)
}

// revealToBuf decrypts and verifies one secret of r.
func revealToBuf(r *Repo, p string) ([]byte, error) {
	if !canReveal(r, p) {
		return nil, fmt.Errorf("%s: you cannot read it", p)
	}

	var buf bytes.Buffer
	if err := r.secret.Reveal(p, &buf); err != nil {
		return nil, fmt.Errorf("reveal %s: %w", p, err)
	}

	return buf.Bytes(), nil
}
