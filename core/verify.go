package core

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
)

// VerifiedUser is a user that has been verified by the audit log.
type VerifiedUser struct {
	Name       string   `json:"name"`
	Groups     []string `json:"groups"`
	SignPubKey []string `json:"sign_pub_key"`
	PubKeys    []string `json:"pub_keys"`
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

func (s *VerifiedState) RequireAdmin(entry *auditEntrySigned) (*VerifiedUser, error) {
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
func (s *VerifiedState) FeedEntry(signer Signer, entry *auditEntry) error {
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

func verifyInit(log *AuditLog, state *VerifiedState, entry *auditEntrySigned, kr Keyring) error {
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

func verifyUserTell(log *AuditLog, state *VerifiedState, entry *auditEntrySigned, kr Keyring) error {
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
	if err := validUserName(tell.User); err != nil {
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

		kr.AddSignPubKey(tell.User, signPubKeyData)
	}

	if len(tell.PubKeys) == 0 {
		return fmt.Errorf("user %s needs at least one public key", tell.User)
	}

	if len(tell.PubKeys) > 10 {
		return fmt.Errorf("user %s may not have more than 10 public keys", tell.User)
	}

	for _, pubKey := range tell.PubKeys {
		recp, err := ParseRecipient(pubKey)
		if err != nil {
			return fmt.Errorf("bad public key %v", pubKey)
		}

		kr.AddRecipient(tell.User, recp)
	}

	state.Users = append(state.Users, VerifiedUser{
		Name:       tell.User,
		SignPubKey: tell.SignPubKeys,
		PubKeys:    tell.PubKeys,
		Groups:     deduplicate(tell.Groups),
	})

	return nil
}

func verifyUserKill(log *AuditLog, state *VerifiedState, entry *auditEntrySigned, kr Keyring) error {
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

	adminUsersFound := 0
	adminName := ""
	for _, user := range state.Users {
		if user.IsAdmin() {
			adminUsersFound++
			adminName = user.Name
		}
	}

	// only one admin there:
	// - if the admin is the one we gonna delete: forbid.
	// - if we delete another user: allow.
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

func verifySecretChange(log *AuditLog, state *VerifiedState, entry *auditEntrySigned) error {
	scd, err := parseDetail[DetailSecretChange](entry)
	if err != nil {
		return fmt.Errorf("parse detail: %w", err)
	}

	if len(scd.Groups) == 0 {
		return fmt.Errorf("groups may not be empty (%s)", scd.RevealedPath)
	}

	// double check nobody inserted ../../ or similar into the revealed path.
	if err := validSecretPathFormat(log.SesamDir, scd.RevealedPath); err != nil {
		return err
	}

	scd.Groups = deduplicate(scd.Groups)
	if !slices.Contains(scd.Groups, "admin") {
		scd.Groups = append(scd.Groups, "admin")
	}

	existingSecret, exists := state.SecretExists(scd.RevealedPath)
	if exists {
		// secret exists
		hasAccess := state.UserHasAccess(entry.ChangedBy, existingSecret.AccessGroups)
		if !hasAccess {
			return fmt.Errorf(
				"user %s may not change details of %s",
				entry.ChangedBy,
				scd.RevealedPath,
			)
		}

		existingSecret.AccessGroups = scd.Groups
	} else {
		hasAccess := state.UserHasAccess(entry.ChangedBy, scd.Groups)
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
			AccessGroups: scd.Groups,
		})
	}

	state.SealRequiredSeqID = entry.SeqID
	return nil
}

func verifySecretRemove(log *AuditLog, state *VerifiedState, entry *auditEntrySigned) error {
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

func verifySeal(log *AuditLog, state *VerifiedState, entry *auditEntrySigned) error {
	sealDetails, err := parseDetail[DetailSeal](entry)
	if err != nil {
		return fmt.Errorf("parse detail: %w", err)
	}

	state.SealRequiredSeqID = 0
	state.LastSealRootHash = sealDetails.RootHash
	return nil
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
func VerifyChain(log *AuditLog, kr Keyring) (*VerifiedState, error) {
	state := VerifiedState{
		auditLog: log,
		keyring:  kr,
	}
	if err := verify(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func Verify(log *AuditLog, kr Keyring) (*VerifiedState, error) {
	if err := verifyInitFileUnchanged(log.SesamDir); err != nil {
		return nil, fmt.Errorf("init file check: %w", err)
	}

	// use an fresh empty state:
	state := VerifiedState{
		auditLog: log,
		keyring:  kr,
	}

	if err := verify(&state); err != nil {
		return nil, err
	}

	// Verify that the latest seal's RootHash matches the signature footers on disk.
	if state.LastSealRootHash != "" {
		sigs, err := readAllSignatures(log.SesamDir)
		if err != nil {
			return nil, fmt.Errorf("reading signatures for root hash check: %w", err)
		}

		sigPtrs := make([]*secretFooter, len(sigs))
		for i := range sigs {
			sigPtrs[i] = &sigs[i]
		}

		diskRootHash := buildRootHash(sigPtrs)
		if diskRootHash != state.LastSealRootHash {
			return nil, fmt.Errorf(
				"root hash mismatch: log says %s, disk says %s",
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

	var previousEntry *auditEntrySigned
	err := log.Iterate(func(idx int, entry *auditEntrySigned) error {
		if entry.SeqID <= newState.VerifiedUntil {
			return nil
		}

		// first do the logical checks & then the signature check.
		// operations like init, tell etc. add keys to the keyring which can be required
		// to verify signatures.
		var err error
		switch entry.Operation {
		case opInit:
			err = verifyInit(log, &newState, entry, kr)
		case opUserTell:
			err = verifyUserTell(log, &newState, entry, kr)
		case opUserKill:
			err = verifyUserKill(log, &newState, entry, kr)
		case opSeal:
			err = verifySeal(log, &newState, entry)
		case opSecretChange:
			err = verifySecretChange(log, &newState, entry)
		case opSecretRemove:
			err = verifySecretRemove(log, &newState, entry)
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

// TODO: Make sure this is called
func (s *VerifiedState) Close() error {
	// NOTE: Not a hard error for now, there might be valid reasons this happened.
	// Could be that sesam was legit interrupted during operation.
	if srs := s.SealRequiredSeqID; srs > 0 {
		slog.Warn(
			"verify: entry required a seal, but none was made after",
			slog.Uint64("seq_id", srs),
		)
	}

	return nil
}
