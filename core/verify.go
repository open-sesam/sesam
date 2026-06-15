package core

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
)

// VerifiedUser is a user that has been verified by the audit log.
type VerifiedUser struct {
	Name       string     `json:"name"`
	Groups     []string   `json:"groups"`
	SignPubKey []string   `json:"sign_pub_key"`
	Recps      Recipients `json:"recipients"`
}

// VerifiedSecret is a secret verified by the audit log.
type VerifiedSecret struct {
	RevealedPath string
	AccessGroups []string
}

// VerifiedState is the state of the repo based on the audit log.
// It might differ from the state defined by the config, which can mean:
//
// - Config was edited by user locally (to add new secrets or users declaratively)
// - Something was tampered with (e.g. Eve added herself as admin)
type VerifiedState struct {
	Users   []VerifiedUser
	Secrets []VerifiedSecret

	// SealRequiredSeqID tells us the entry that required a seal but didn't have one yet.
	// If a seal was provided, it is set back to 0.
	SealRequiredSeqID uint64

	// VerifiedUntil tells us until which seq_id we verified.
	// This is useful to update the state which entries that were added later.
	VerifiedUntil uint64

	// LastSealRootHash is the RootHash from the most recent seal entry.
	// Compared against disk after replay to detect file substitution.
	LastSealRootHash string

	auditLog *AuditLog
	keyring  Keyring
	pluginUI *PluginUI
}

func (vu *VerifiedUser) IsAdmin() bool {
	return slices.Contains(vu.Groups, "admin")
}

func (s *VerifiedState) UserExists(user string) (*VerifiedUser, bool) {
	idx := slices.IndexFunc(s.Users, func(u VerifiedUser) bool {
		return u.Name == user
	})

	if idx < 0 {
		return nil, false
	}

	return &s.Users[idx], true
}

func (s *VerifiedState) SecretExists(revealedPath string) (*VerifiedSecret, bool) {
	idx := slices.IndexFunc(s.Secrets, func(vs VerifiedSecret) bool {
		return vs.RevealedPath == revealedPath
	})

	if idx < 0 {
		return nil, false
	}

	return &s.Secrets[idx], true
}

// UserHasAccess checks if `user` is in one of `grous` and has therefore access.
func (s *VerifiedState) UserHasAccess(user string, groups []string) bool {
	idx := slices.IndexFunc(s.Users, func(u VerifiedUser) bool {
		return u.Name == user
	})

	if idx < 0 {
		return false
	}

	groupMap := groupsToMap(groups)
	for _, group := range s.Users[idx].Groups {
		if groupMap[group] {
			return true
		}
	}

	return false
}

func (s *VerifiedState) UsersForSecret(revealedPath string) []string {
	idx := slices.IndexFunc(s.Secrets, func(vs VerifiedSecret) bool {
		return vs.RevealedPath == revealedPath
	})
	if idx < 0 {
		return nil
	}

	secret := &s.Secrets[idx]
	groups := groupsToMap(secret.AccessGroups)

	var users []string
	for _, user := range s.Users {
		for _, g := range user.Groups {
			if groups[g] {
				users = append(users, user.Name)
				break
			}
		}
	}

	return users
}

func (s *VerifiedState) AdminUserCount() (adminUsersFound int, adminName string) {
	for _, user := range s.Users {
		if user.IsAdmin() {
			adminUsersFound++
			adminName = user.Name
		}
	}

	return adminUsersFound, adminName
}

// SealerAuthorized reports whether `user` is allowed to seal `revealedPath`,
// i.e. whether the secret exists in the verified state and `user` has
// access to it via group membership. Used by reveal- and integrity-time
// checks to detect substitution attacks where a known signer produces a
// footer for a path they never had access to.
func (s *VerifiedState) SealerAuthorized(user, revealedPath string) bool {
	secret, ok := s.SecretExists(revealedPath)
	if !ok {
		return false
	}
	return s.UserHasAccess(user, secret.AccessGroups)
}

func (s *VerifiedState) UserForGroups(groups []string) []string {
	users := make([]string, 0)
	groupMap := groupsToMap(groups)

outer:
	for _, vuser := range s.Users {
		for _, vgroup := range vuser.Groups {
			if groupMap[vgroup] {
				// user matches one of those groups.
				users = append(users, vuser.Name)
				continue outer
			}
		}
	}

	return users
}

func (s *VerifiedState) RequireAdmin(entry *AuditEntrySigned) (*VerifiedUser, error) {
	adminUser, exists := s.UserExists(entry.ChangedBy)
	if !exists {
		return nil, fmt.Errorf("user %s does not exist at seq_id=%d", entry.ChangedBy, entry.SeqID)
	}

	if !adminUser.IsAdmin() {
		return nil, fmt.Errorf("user %s was not admin at seq_id %d", entry.ChangedBy, entry.SeqID)
	}

	return adminUser, nil
}

// FeedEntry adds `entry` to audit log, then updates the state by verifying the entry.
func (s *VerifiedState) FeedEntry(signer Signer, entry *AuditEntry) error {
	if _, err := s.auditLog.AddEntry(signer, entry, func() error {
		return verify(s)
	}); err != nil {
		return fmt.Errorf("audit add entry: %w", err)
	}

	return nil
}

func groupsToMap(groups []string) map[string]bool {
	groupMap := make(map[string]bool, len(groups)+1)
	for _, group := range groups {
		groupMap[group] = true
	}
	groupMap["admin"] = true
	return groupMap
}

func verifyInit(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned, kr Keyring) error {
	if entry.SeqID != 1 {
		return fmt.Errorf("init at wrong seq_id: %d (!= 1)", entry.SeqID)
	}

	if eh := entry.Hash(); eh != log.InitHash {
		return fmt.Errorf("audit log has been possibly truncated: %s != %s", eh, log.InitHash)
	}

	initDetail, err := parseDetail[DetailInit](entry)
	if err != nil {
		return fmt.Errorf("parse init detail: %w", err)
	}

	admin := &initDetail.Admin
	if entry.ChangedBy != admin.User {
		return fmt.Errorf("init changed_by (%s) does not match admin user (%s)", entry.ChangedBy, admin.User)
	}

	if !slices.Contains(admin.Groups, "admin") {
		return fmt.Errorf("init admin user %s is not in the admin group", admin.User)
	}

	return registerUser(state, admin, kr)
}

func verifyUserTell(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned, kr Keyring) error {
	tellDetails, err := parseDetail[DetailUserTell](entry)
	if err != nil {
		return fmt.Errorf("parse user.tell detail: %w", err)
	}

	if _, err := state.RequireAdmin(entry); err != nil {
		return err
	}

	if entry.ChangedBy == tellDetails.User {
		return fmt.Errorf("users cannot add themself (seq_id=%d)", entry.SeqID)
	}

	state.SealRequiredSeqID = entry.SeqID
	return registerUser(state, tellDetails, kr)
}

// registerUser adds a user's keys to the keyring and state.
// Shared by verifyInit (initial admin) and verifyUserTell.
func registerUser(state *VerifiedState, tell *DetailUserTell, kr Keyring) error {
	if err := ValidUserName(tell.User); err != nil {
		return fmt.Errorf("invalid user name %q: %w", tell.User, err)
	}

	if _, exists := state.UserExists(tell.User); exists {
		return fmt.Errorf("user %s already exists", tell.User)
	}

	if len(tell.SignPubKeys) == 0 {
		return fmt.Errorf("user %s needs at least one signing pub key", tell.User)
	}

	if len(tell.SignPubKeys) > 10 {
		return fmt.Errorf("user %s may not have more than 10 signing keys", tell.User)
	}

	for _, signPubKey := range tell.SignPubKeys {
		signPubKeyData, _, err := multicodeDecode(signPubKey)
		if err != nil {
			return fmt.Errorf("bad signing key %v", signPubKey)
		}

		if err := kr.AddSignPubKey(tell.User, signPubKeyData); err != nil {
			// will trigger on duplicate keys.
			return err
		}
	}

	if len(tell.PubKeys) == 0 {
		return fmt.Errorf("user %s needs at least one public key", tell.User)
	}

	if len(tell.PubKeys) > 10 {
		return fmt.Errorf("user %s may not have more than 10 public keys", tell.User)
	}

	var recps Recipients
	for _, pubKey := range tell.PubKeys {
		recp, err := ParseRecipient(pubKey.Key, state.pluginUI)
		if err != nil {
			return fmt.Errorf("bad public key %v", pubKey)
		}

		recp.Source = pubKey.Source
		if err := kr.AddRecipient(tell.User, recp); err != nil {
			// will trigger on duplicate keys.
			return err
		}

		recps = append(recps, recp)
	}

	state.Users = append(state.Users, VerifiedUser{
		Name:       tell.User,
		SignPubKey: tell.SignPubKeys,
		Recps:      recps,
		Groups:     deduplicate(tell.Groups),
	})

	return nil
}

func verifyUserRename(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned, kr Keyring) error {
	if _, err := state.RequireAdmin(entry); err != nil {
		return err
	}

	renameDetails, err := parseDetail[DetailUserRename](entry)
	if err != nil {
		return fmt.Errorf("parse user rename detail: %w", err)
	}

	if err := ValidUserName(renameDetails.NewName); err != nil {
		return fmt.Errorf("invalid new user name %q", renameDetails.NewName)
	}

	if _, exists := state.UserExists(renameDetails.NewName); exists {
		return fmt.Errorf("new user already exists: %s", renameDetails.NewName)
	}

	user, exists := state.UserExists(renameDetails.OldName)
	if !exists {
		return fmt.Errorf(
			"user %s to rename does not exist; seq_id=%d",
			renameDetails.OldName,
			entry.SeqID,
		)
	}

	kr.RenameUser(renameDetails.OldName, renameDetails.NewName)
	user.Name = renameDetails.NewName
	return nil
}

func verifyUserChangeGroups(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned, kr Keyring) error {
	if _, err := state.RequireAdmin(entry); err != nil {
		return err
	}

	ucg, err := parseDetail[DetailUserChangeGroups](entry)
	if err != nil {
		return fmt.Errorf("parse user change groups detail: %w", err)
	}

	user, exists := state.UserExists(ucg.User)
	if !exists {
		return fmt.Errorf(
			"user %s to change groups does not exist; seq_id=%d",
			ucg.User,
			entry.SeqID,
		)
	}

	adminUsersFound, adminName := state.AdminUserCount()
	if adminUsersFound == 1 && adminName == user.Name {
		if !slices.Contains(ucg.NewGroups, "admin") {
			return fmt.Errorf(
				"trying to change access of last admin user to %v: %s (seq_id=%d)",
				user.Name,
				ucg.NewGroups,
				entry.SeqID,
			)
		}
	}

	user.Groups = deduplicate(ucg.NewGroups)
	state.SealRequiredSeqID = entry.SeqID
	return nil
}

func verifyUserKill(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned, kr Keyring) error {
	if _, err := state.RequireAdmin(entry); err != nil {
		return err
	}

	killDetails, err := parseDetail[DetailUserKill](entry)
	if err != nil {
		return fmt.Errorf("parse user.kill detail: %w", err)
	}

	user, exists := state.UserExists(killDetails.User)
	if !exists {
		return fmt.Errorf(
			"user %s to remove does not exist; seq_id=%d",
			killDetails.User,
			entry.SeqID,
		)
	}

	// only one admin there:
	// - if the admin is the one we gonna delete: forbid.
	// - if we delete another user: allow.
	adminUsersFound, adminName := state.AdminUserCount()
	if adminUsersFound == 1 && adminName == user.Name {
		return fmt.Errorf("trying to delete last admin user: %s (seq_id=%d)", user.Name, entry.SeqID)
	}

	// Looks good, change state:
	kr.DeleteUser(user.Name)
	state.SealRequiredSeqID = entry.SeqID
	state.Users = slices.DeleteFunc(state.Users, func(vu VerifiedUser) bool {
		return vu.Name == killDetails.User
	})

	return nil
}

func verifyUserAddRecipients(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned, kr Keyring) error {
	if _, err := state.RequireAdmin(entry); err != nil {
		return err
	}

	duar, err := parseDetail[DetailUserAddRecipients](entry)
	if err != nil {
		return fmt.Errorf("parse user.add_recipients detail: %w", err)
	}

	user, exists := state.UserExists(duar.User)
	if !exists {
		return fmt.Errorf(
			"user %s to add recipients to does not exist; seq_id=%d",
			duar.User,
			entry.SeqID,
		)
	}

	var recps Recipients
	for _, pubKey := range duar.PubKeys {
		recp, err := ParseRecipient(pubKey.Key, state.pluginUI)
		if err != nil {
			return fmt.Errorf("bad public key %v", pubKey)
		}

		recp.Source = pubKey.Source
		if err := kr.AddRecipient(duar.User, recp); err != nil {
			// will trigger on duplicate keys.
			return err
		}

		recps = append(recps, recp)
	}

	user.Recps = append(user.Recps, recps...)
	return nil
}

func verifyUserRmRecipients(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned, kr Keyring) error {
	if _, err := state.RequireAdmin(entry); err != nil {
		return err
	}

	durr, err := parseDetail[DetailUserRmRecipients](entry)
	if err != nil {
		return fmt.Errorf("parse user.rm_recipients detail: %w", err)
	}

	user, exists := state.UserExists(durr.User)
	if !exists {
		return fmt.Errorf(
			"user %s to remove recipients from does not exist; seq_id=%d",
			durr.User,
			entry.SeqID,
		)
	}

	for _, pubKey := range durr.PubKeys {
		toDelete, err := ParseRecipient(pubKey.Key, state.pluginUI)
		if err != nil {
			return fmt.Errorf("bad public key %v", pubKey)
		}

		if err := kr.RemoveRecipient(user.Name, toDelete); err != nil {
			// kr.RemoveRecipient already checks that at least one recipient is left
			return err
		}

		user.Recps = slices.DeleteFunc(user.Recps, func(r *Recipient) bool {
			return toDelete.Equal(r)
		})
	}

	return nil
}

func verifySecretAdd(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned) error {
	scd, err := parseDetail[DetailSecretAdd](entry)
	if err != nil {
		return fmt.Errorf("parse detail: %w", err)
	}

	// double check nobody inserted ../../ or similar into the revealed path.
	if err := validSecretPathFormat(log.SesamDir, scd.RevealedPath); err != nil {
		return err
	}

	scd.AccessGroups = deduplicate(scd.AccessGroups)
	if !slices.Contains(scd.AccessGroups, "admin") {
		scd.AccessGroups = append(scd.AccessGroups, "admin")
	}

	_, exists := state.SecretExists(scd.RevealedPath)
	if exists {
		return fmt.Errorf("cannot add already existing secret: %s", scd.RevealedPath)
	}

	hasAccess := state.UserHasAccess(entry.ChangedBy, scd.AccessGroups)
	if !hasAccess {
		return fmt.Errorf(
			"would add secret that %s has no access to: %s",
			entry.ChangedBy,
			scd.RevealedPath,
		)
	}

	// secret does not exist
	state.Secrets = append(state.Secrets, VerifiedSecret{
		RevealedPath: scd.RevealedPath,
		AccessGroups: scd.AccessGroups,
	})

	state.SealRequiredSeqID = entry.SeqID
	return nil
}

func verifySecretChangeAccess(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned) error {
	sca, err := parseDetail[DetailSecretChangeAccess](entry)
	if err != nil {
		return fmt.Errorf("parse detail: %w", err)
	}

	existingSecret, exists := state.SecretExists(sca.RevealedPath)
	if !exists {
		return fmt.Errorf("trying to change access of not existing secret: %s", sca.RevealedPath)
	}

	hasAccess := state.UserHasAccess(entry.ChangedBy, existingSecret.AccessGroups)
	if !hasAccess {
		return fmt.Errorf(
			"would change access to secret that %s has no access to: %s",
			entry.ChangedBy,
			sca.RevealedPath,
		)
	}

	sca.AccessGroups = deduplicate(sca.AccessGroups)
	if !slices.Contains(sca.AccessGroups, "admin") {
		sca.AccessGroups = append(sca.AccessGroups, "admin")
	}

	existingSecret.AccessGroups = sca.AccessGroups
	state.SealRequiredSeqID = entry.SeqID
	return nil
}

func verifySecretMove(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned) error {
	scr, err := parseDetail[DetailSecretMove](entry)
	if err != nil {
		return fmt.Errorf("parse detail: %w", err)
	}

	if err := validSecretPathFormat(log.SesamDir, scr.NewRevealedPath); err != nil {
		return err
	}

	if _, exists := state.SecretExists(scr.NewRevealedPath); exists {
		return fmt.Errorf("cannot move secret over existing secret: %q", scr.NewRevealedPath)
	}

	existingSecret, exists := state.SecretExists(scr.OldRevealedPath)
	if !exists {
		return fmt.Errorf("trying to rename not existing secret: %s", scr.OldRevealedPath)
	}

	hasAccess := state.UserHasAccess(entry.ChangedBy, existingSecret.AccessGroups)
	if !hasAccess {
		return fmt.Errorf(
			"would rename secret that %s has no access to: %s",
			entry.ChangedBy,
			scr.OldRevealedPath,
		)
	}

	// change in state to new name:
	existingSecret.RevealedPath = scr.NewRevealedPath
	state.SealRequiredSeqID = entry.SeqID
	return nil
}

func verifySecretRemove(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned) error {
	srd, err := parseDetail[DetailSecretRemove](entry)
	if err != nil {
		return fmt.Errorf("parse detail: %w", err)
	}

	// double check nobody inserted ../../ or similar into the revealed path.
	if err := validSecretPathFormat(log.SesamDir, srd.RevealedPath); err != nil {
		return err
	}

	s, exists := state.SecretExists(srd.RevealedPath)
	if !exists {
		return fmt.Errorf(
			"secret %s does not exist, cannot remove (seq_id=%d)",
			srd.RevealedPath,
			entry.SeqID,
		)
	}

	if !state.UserHasAccess(entry.ChangedBy, s.AccessGroups) {
		return fmt.Errorf(
			"user %s has no access, cannot remove (seq_id=%d)",
			entry.ChangedBy,
			entry.SeqID,
		)
	}

	state.Secrets = slices.DeleteFunc(state.Secrets, func(s VerifiedSecret) bool {
		return s.RevealedPath == srd.RevealedPath
	})

	return nil
}

func verifySeal(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned) error {
	sealDetails, err := parseDetail[DetailSeal](entry)
	if err != nil {
		return fmt.Errorf("parse detail: %w", err)
	}

	state.SealRequiredSeqID = 0
	state.LastSealRootHash = sealDetails.RootHash
	return nil
}

// recoverIncompleteSeal finishes (or rolls back) a SealAll that crashed.
//
// SealAll's ordering is: stage -> audit entry -> swap -> reap old stage.
// The audit entry is the commit point: once it lands, the new state is
// final and recovery must reach it; before it lands, the staged work is
// discardable.
//
// On the next load we hash both .sesam/seal-stage and .sesam/objects and
// compare them against the latest seal's RootHash in the audit log:
//
//   - no seal entry yet or live matches the log -> stage is leftover, drop it.
//   - stage matches the log -> swap was pending, finish it.
//   - neither matches -> the log committed a state nothing on disk holds.
//     Cannot reconcile; bail and let the user investigate.
func recoverIncompleteSeal(sesamDir string, vstate *VerifiedState) error {
	stageDir := filepath.Join(sesamDir, ".sesam", "seal-stage")
	objectsDir := filepath.Join(sesamDir, ".sesam", "objects")

	if !PathExists(stageDir) {
		return nil
	}

	objectSigs, err := readAllSignaturesForDir(objectsDir)
	if err != nil {
		return err
	}
	objectsRootHash := buildRootHash(objectSigs)

	if vstate.LastSealRootHash == "" {
		// Crashed during the very first SealAll, before any audit entry
		// was written. Stage holds uncommitted work; discard it.
		return os.RemoveAll(stageDir)
	}

	if vstate.LastSealRootHash == objectsRootHash {
		// Audit entry written and swap done, just stage dir not yet deleted.
		return os.RemoveAll(stageDir)
	}

	stageSigs, err := readAllSignaturesForDir(stageDir)
	if err != nil {
		return err
	}
	stageRootHash := buildRootHash(stageSigs)

	if vstate.LastSealRootHash == stageRootHash {
		// Audit entry written, but stage not yet swapped. Finish it,
		// then reap the now-old tree that lands back in stage.
		if err := atomicSwapDirs(stageDir, objectsDir); err != nil {
			return err
		}
		return os.RemoveAll(stageDir)
	}

	// Log committed a state that exists neither in stage nor in objects.
	// Likely cause: the stage dir was modified out-of-band after the crash.
	return fmt.Errorf(
		"seal recover: root hash mismatch between stage dir (%s) and audit log (%s)",
		stageRootHash,
		vstate.LastSealRootHash,
	)
}

// VerifyChain replays the audit log into a fresh VerifiedState without the
// expensive disk-side checks done by Verify (init-file unchanged across git
// history, root-hash of all .sesam files on disk). This is what callers
// that already trust the file source need - notably the git smudge filter,
// which reads the audit log from the consistent git index and only wants
// per-file sealed_by enforcement.
//
// Use Verify when you also want disk and git-history consistency
// (`sesam reveal`, `sesam verify --all`).
// VerifyChain replays the audit log and returns the derived VerifiedState.
// pluginUI is used to construct plugin.Recipient objects when a user's public
// key is a plugin recipient; the stored *PluginUI travels with each Recipient
// and is consulted at seal-time if the plugin asks for user interaction. Pass
// nil to default to a non-interactive UI (plugins will refuse to prompt).
func VerifyChain(log *AuditLog, kr Keyring, pluginUI *PluginUI) (*VerifiedState, error) {
	state := VerifiedState{
		auditLog: log,
		keyring:  kr,
		pluginUI: pluginUI,
	}
	if err := verify(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

// Verify is like VerifyChain but additionally checks the trust-anchor file
// (.sesam/audit/init) and the latest seal's root-hash against the on-disk
// secret footers. See [VerifyChain] for pluginUI semantics.
func Verify(log *AuditLog, kr Keyring, pluginUI *PluginUI) (*VerifiedState, error) {
	if _, err := verifyInitFileUnchanged(log.SesamDir); err != nil {
		return nil, fmt.Errorf("init file check: %w", err)
	}

	// use an fresh empty state:
	state := VerifiedState{
		auditLog: log,
		keyring:  kr,
		pluginUI: pluginUI,
	}

	if err := verify(&state); err != nil {
		return nil, err
	}

	// Reconcile disk with the log: finish a pending swap or drop a
	// stale staging dir from a previously crashed SealAll. Runs after
	// verify(state) so the log (and thus LastSealRootHash) is trusted.
	if err := recoverIncompleteSeal(log.SesamDir, &state); err != nil {
		return nil, err
	}

	// Verify that the latest seal's RootHash matches the signature footers on disk.
	if state.LastSealRootHash != "" {
		sigs, err := readAllSignatures(log.SesamDir)
		if err != nil {
			return nil, fmt.Errorf("reading signatures for root hash check: %w", err)
		}

		diskRootHash := buildRootHash(sigs)
		if diskRootHash != state.LastSealRootHash {
			return nil, fmt.Errorf(
				"root hash mismatch: log says %s, disk says %s (try --verify-mode no-disk)",
				state.LastSealRootHash,
				diskRootHash,
			)
		}
	}

	return &state, nil
}

func verify(state *VerifiedState) error {
	log := state.auditLog
	kr := state.keyring
	newState := *state

	var previousEntry *AuditEntrySigned
	err := log.Iterate(func(idx int, entry *AuditEntrySigned) error {
		if entry.SeqID <= newState.VerifiedUntil {
			return nil
		}

		// first do the logical checks & then the signature check.
		// operations like init, tell etc. add keys to the keyring which can be required
		// to verify signatures.
		var err error
		switch entry.Operation {
		case OpInit:
			err = verifyInit(log, &newState, entry, kr)
		case OpUserTell:
			err = verifyUserTell(log, &newState, entry, kr)
		case OpUserChangeGroups:
			err = verifyUserChangeGroups(log, &newState, entry, kr)
		case OpUserAddRecipients:
			err = verifyUserAddRecipients(log, &newState, entry, kr)
		case OpUserRmRecipients:
			err = verifyUserRmRecipients(log, &newState, entry, kr)
		case OpSeal:
			err = verifySeal(log, &newState, entry)
		case OpSecretAdd:
			err = verifySecretAdd(log, &newState, entry)
		case OpSecretRemove:
			err = verifySecretRemove(log, &newState, entry)
		case OpSecretChangeAccess:
			err = verifySecretChangeAccess(log, &newState, entry)
		case OpSecretMove:
			err = verifySecretMove(log, &newState, entry)
		case OpUserKill, OpUserRename:
			// done later
		default:
			err = fmt.Errorf("unexpected core.Operation: %#v", entry.Operation)
		}

		if err != nil {
			return err
		}

		// check the signature
		signatureUser, err := entry.Verify(kr)
		if err != nil {
			return fmt.Errorf("failed to verify signature on entry %d: %w", entry.SeqID, err)
		}

		if signatureUser != entry.ChangedBy {
			return fmt.Errorf("signature was made by %s, not %s (seq_id=%d)", signatureUser, entry.ChangedBy, entry.SeqID)
		}

		// we verify operations there that need to carry out their keyring changes after verify.
		// example: an admin renames himself as single user -> if keyring was already changed then
		// the verify check would have failed if we'd do it before because entry.ChangedBy is with the old name.
		switch entry.Operation {
		case OpUserKill:
			err = verifyUserKill(log, &newState, entry, kr)
		case OpUserRename:
			err = verifyUserRename(log, &newState, entry, kr)
		}

		if err != nil {
			return err
		}

		if previousEntry != nil {
			prevJSON, err := json.Marshal(previousEntry)
			if err != nil {
				return fmt.Errorf("marshal previous entry: %w", err)
			}

			expectedHash := hashData(prevJSON)
			if expectedHash != entry.PreviousHash {
				return fmt.Errorf(
					"broken chain at idx %d: %s != %s",
					idx,
					expectedHash,
					entry.PreviousHash,
				)
			}
		}

		previousEntry = entry
		newState.VerifiedUntil = entry.SeqID
		return nil
	})
	if err != nil {
		return err
	}

	*state = newState
	return nil
}

func (s *VerifiedState) Close() error {
	// NOTE: Not a hard error for now, there might be valid reasons this happened.
	// Could be that sesam was legit interrupted during operation.
	if srs := s.SealRequiredSeqID; srs > 0 {
		slog.Warn(
			"verify: a seal is pending - please run `sesam seal` before committing!",
			slog.Uint64("seq_id", srs),
		)
	}

	return nil
}
