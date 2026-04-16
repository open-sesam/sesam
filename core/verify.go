package core

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
)

// VerifiedUser is a user that has been verified by the audit log.
type VerifiedUser struct {
	Name       string
	Groups     []string
	SignPubKey []string
	PubKeys    []string
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
	SealRequiredSeqID int

	// VerifiedUntil tells us until which seq_id we verified.
	// This is useful to update the state which entries that were added later.
	VerifiedUntil int

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

// Update verifies entries that have been added at runtime
func (s *VerifiedState) Update() error {
	return verify(s)
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

	state.SealRequiredSeqID = int(entry.SeqID)
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

	for _, signPubKey := range tell.SignPubKeys {
		signPubKeyData, _, err := multicodeDecode(signPubKey)
		if err != nil {
			return fmt.Errorf("bad signing key %v", signPubKey)
		}

		kr.AddSignPubKey(tell.User, signPubKeyData)
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
	state.SealRequiredSeqID = int(entry.SeqID)
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

	scd.Groups = deduplicate(scd.Groups)
	if !slices.Contains(scd.Groups, "admin") {
		scd.Groups = append(scd.Groups, "admin")
	}

	existsIdx := slices.IndexFunc(state.Secrets, func(vs VerifiedSecret) bool {
		return vs.RevealedPath == scd.RevealedPath
	})

	if existsIdx >= 0 {
		// secret exists
		hasAccess := state.UserHasAccess(entry.ChangedBy, state.Secrets[existsIdx].AccessGroups)
		if !hasAccess {
			return fmt.Errorf(
				"user %s may not change details of %s",
				entry.ChangedBy,
				scd.RevealedPath,
			)
		}

		state.Secrets[existsIdx] = VerifiedSecret{
			RevealedPath: scd.RevealedPath,
			AccessGroups: scd.Groups,
		}
	} else {
		// secret does not exist
		state.Secrets = append(state.Secrets, VerifiedSecret{
			RevealedPath: scd.RevealedPath,
			AccessGroups: scd.Groups,
		})
	}

	state.SealRequiredSeqID = int(entry.SeqID)
	return nil
}

func verifySecretRemove(log *AuditLog, state *VerifiedState, entry *auditEntrySigned) error {
	srd, err := parseDetail[DetailSecretRemove](entry)
	if err != nil {
		return fmt.Errorf("parse detail: %w", err)
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

func Verify(log *AuditLog, kr Keyring) (*VerifiedState, error) {
	if err := verifyInitFileUnchanged(log.RepoDir); err != nil {
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

	// Verify that the latest seal's RootHash matches the .sig.json files on disk.
	if state.LastSealRootHash != "" {
		sigs, err := readAllSignatures(log.RepoDir)
		if err != nil {
			return nil, fmt.Errorf("reading signatures for root hash check: %w", err)
		}

		sigPtrs := make([]*secretSignature, len(sigs))
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

	var previousEntry *auditEntrySigned
	err := log.Iterate(func(idx int, entry *auditEntrySigned) error {
		if entry.SeqID <= uint64(state.VerifiedUntil) {
			return nil
		}

		// first do the logical checks & then the signature check.
		// operations like init, tell etc. add keys to the keyring which can be required
		// to verify signatures.
		var err error
		switch entry.Operation {
		case opInit:
			err = verifyInit(log, state, entry, state.keyring)
		case opUserTell:
			err = verifyUserTell(log, state, entry, state.keyring)
		case opUserKill:
			err = verifyUserKill(log, state, entry, state.keyring)
		case opSeal:
			err = verifySeal(log, state, entry)
		case opSecretChange:
			err = verifySecretChange(log, state, entry)
		case opSecretRemove:
			err = verifySecretRemove(log, state, entry)
		default:
			err = fmt.Errorf("unexpected core.Operation: %#v", entry.Operation)
		}

		if err != nil {
			return err
		}

		// check the signature
		signatureUser, err := entry.Verify(state.keyring)
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
		state.VerifiedUntil = int(entry.SeqID)
		return nil
	})
	if err != nil {
		return err
	}

	// TODO: Is that a hard error? Or should we just warn here?
	// Could be that sesam was legit interrupted during operation.
	if srs := state.SealRequiredSeqID; srs > 0 {
		slog.Warn("verify: entry required a seal, but none was made after", slog.Int("seq_id", srs))
	}

	return nil
}
