package core

import (
	"encoding/json"
	"fmt"
	"slices"
)

type VerifiedUser struct {
	Name       string
	Groups     []string
	SignPubKey []string
	PubKeys    []string
}

func (vu *VerifiedUser) IsAdmin() bool {
	return slices.Contains(vu.Groups, "admin")
}

type VerifiedGroup struct {
	Name string
}

type VerifiedSecret struct {
	// TODO: Do we verify also other attributes of secrets here? like name, rotation params, types, ...?
	RevealedPath string
	AccessGroups []string
}

type VerifiedState struct {
	Users   []VerifiedUser
	Secrets []VerifiedSecret

	// SealRequiredSeqID tells us the entry that required a seal but didn't have one yet.
	// If a seal was provided, it is set back to 0.
	SealRequiredSeqID int
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

// UserHasAccess checks if `user` is in one of `grous` and has therefore access.
func (s *VerifiedState) UserHasAccess(user string, groups []string) bool {
	groupMap := make(map[string]bool, len(groups))
	for _, group := range groups {
		groupMap[group] = true
	}

	// admin has implicit access to all, double check it is added.
	groupMap["admin"] = true

	idx := slices.IndexFunc(s.Users, func(u VerifiedUser) bool {
		return u.Name == user
	})

	for _, group := range s.Users[idx].Groups {
		if groupMap[group] {
			return true
		}
	}

	return false
}

func (s *VerifiedState) RequireAdmin(entry *AuditEntrySigned) (*VerifiedUser, error) {
	adminUser, exists := s.UserExists(entry.ChangedBy)
	if !exists {
		return nil, fmt.Errorf("user %s already existed at seq_id=%d", entry.ChangedBy, entry.SeqID)
	}

	if !adminUser.IsAdmin() {
		return nil, fmt.Errorf("user %s was not admin at seq_id %d", entry.ChangedBy, entry.SeqID)
	}

	return adminUser, nil
}

func verifyInit(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned) error {
	if entry.SeqID != 1 {
		return fmt.Errorf("init at wrong seq_id: %d (!= 1)", entry.SeqID)
	}

	// compare with .sesam/audit/init; should always be the same.
	if eh := entry.Hash(); eh != log.InitHash {
		return fmt.Errorf("audit log has been possibly truncated: %s != %s", eh, log.InitHash)
	}

	return nil
}

func verifyUserTell(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned, kr Keyring) error {
	tellDetails, err := ParseDetail[DetailUserTell](entry)
	if err != nil {
		return err
	}

	if entry.SeqID == 2 {
		// BOOTSTRAP: After init we create an initial admin user.
		if len(state.Users) != 0 {
			return fmt.Errorf("there are already existing users after init")
		}

		if entry.ChangedBy != tellDetails.User {
			return fmt.Errorf("bootstrap user has to add himself")
		}
	} else {
		if _, err := state.RequireAdmin(entry); err != nil {
			return err
		}

		if entry.ChangedBy == tellDetails.User {
			return fmt.Errorf("users cannot add themself (seq_id=%d)", entry.SeqID)
		}
	}

	_, exists := state.UserExists(tellDetails.User)
	if exists {
		return fmt.Errorf("user %s already existed at seq_id=%d", tellDetails.User, entry.SeqID)
	}

	// Add signing keys:
	for _, signPubKey := range tellDetails.SignPubKeys {
		signPubKeyData, _, err := MulticodeDecode(signPubKey)
		if err != nil {
			return fmt.Errorf("bad signing key %v", signPubKey)
		}

		kr.AddSignPubKey(tellDetails.User, signPubKeyData)
	}

	for _, pubKey := range tellDetails.PubKeys {
		recp, err := ParseRecipient(pubKey)
		if err != nil {
			return fmt.Errorf("bad public key %v", pubKey)
		}

		kr.AddRecipient(tellDetails.User, recp)
	}

	state.SealRequiredSeqID = int(entry.SeqID)
	state.Users = append(state.Users, VerifiedUser{
		Name:       tellDetails.User,
		SignPubKey: tellDetails.SignPubKeys,
		PubKeys:    tellDetails.PubKeys,
	})

	return nil
}

func verifyUserKill(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned, kr Keyring) error {
	if _, err := state.RequireAdmin(entry); err != nil {
		return err
	}

	tellDetails, err := ParseDetail[DetailUserTell](entry)
	if err != nil {
		return err
	}

	user, exists := state.UserExists(tellDetails.User)
	if !exists {
		return fmt.Errorf("user %s to remove does not exist; seq_id=%d", tellDetails.User, entry.SeqID)
	}

	kr.DeleteUser(user.Name)

	state.SealRequiredSeqID = int(entry.SeqID)
	state.Users = append(state.Users, VerifiedUser{
		Name:       user.Name,
		SignPubKey: tellDetails.SignPubKeys,
		PubKeys:    tellDetails.PubKeys,
	})

	return nil
}

func verifySecretChange(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned) error {
	secretChangeDetails, err := ParseDetail[DetailSecretChange](entry)
	if err != nil {
		return fmt.Errorf("parse detail: %w", err)
	}

	if len(secretChangeDetails.Groups) == 0 {
		return fmt.Errorf("groups may not be empty (%s)", secretChangeDetails.RevealedPath)
	}

	// groupMap := make(map[])

	// TODO: Check if groups have duplicates.
	// TODO: Check if user exists.
	// TODO: Check if admin is not in the groups.
	// TODO: Check if the file really exists? That might not be the case if it was removed later. So need to be done after the audit log verify.

	existsIdx := slices.IndexFunc(state.Secrets, func(vs VerifiedSecret) bool {
		return vs.RevealedPath == secretChangeDetails.RevealedPath
	})

	if existsIdx >= 0 {
		// secret exists
		hasAccess := state.UserHasAccess(entry.ChangedBy, secretChangeDetails.Groups)
		if !hasAccess {
			return fmt.Errorf(
				"user %s may not change details of %s",
				entry.ChangedBy,
				secretChangeDetails.RevealedPath,
			)
		}

		state.Secrets[existsIdx] = VerifiedSecret{
			RevealedPath: secretChangeDetails.RevealedPath,
			AccessGroups: secretChangeDetails.Groups,
		}
	} else {
		// secret does not exist
		state.Secrets = append(state.Secrets, VerifiedSecret{
			RevealedPath: secretChangeDetails.RevealedPath,
			AccessGroups: secretChangeDetails.Groups,
		})
	}

	state.SealRequiredSeqID = int(entry.SeqID)
	return nil
}

func verifySecretRemove(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned) error {
	secretRemoveDetails, err := ParseDetail[DetailSecretRemove](entry)
	if err != nil {
		return fmt.Errorf("parse detail: %w", err)
	}

	// TODO: check if user is allowed to do this.

	exists := slices.ContainsFunc(state.Secrets, func(vs VerifiedSecret) bool {
		return vs.RevealedPath == secretRemoveDetails.RevealedPath
	})

	if !exists {
		return fmt.Errorf("secret %s does not exist, cannot remove", secretRemoveDetails.RevealedPath)
	}

	state.Secrets = slices.DeleteFunc(state.Secrets, func(s VerifiedSecret) bool {
		return s.RevealedPath == secretRemoveDetails.RevealedPath
	})

	return nil
}

func verifySeal(log *AuditLog, state *VerifiedState, entry *AuditEntrySigned) error {
	sealDetails, err := ParseDetail[DetailSeal](entry)
	if err != nil {
		return fmt.Errorf("parse detail: %w", err)
	}

	state.SealRequiredSeqID = 0
	_ = sealDetails // TODO: do the actual verification.
	return nil
}

func Verify(log *AuditLog, kr Keyring) (*VerifiedState, error) {
	var state VerifiedState

	var previousEntry *AuditEntrySigned
	err := log.Iterate(func(idx int, entry *AuditEntrySigned) error {
		// check the signature
		signatureUser, err := entry.Verify(log.Keyring)
		if err != nil {
			return fmt.Errorf("failed to verify signature on entry %d: %w", idx, err)
		}

		if signatureUser != entry.ChangedBy {
			return fmt.Errorf("signature was made by %s, not %s (seq_id=%d)", signatureUser, entry.ChangedBy, entry.SeqID)
		}

		if previousEntry != nil {
			prevJSON, err := json.Marshal(previousEntry)
			if err != nil {
				return fmt.Errorf("marshal previous entry: %w", err)
			}

			expectedHash := Hash(prevJSON)
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
		switch entry.Operation {
		case OpInit:
			return verifyInit(log, &state, entry)
		case OpUserTell:
			return verifyUserTell(log, &state, entry, kr)
		case OpUserKill:
			return verifyUserKill(log, &state, entry, kr)
		case OpSeal:
			return verifySeal(log, &state, entry)
		case OpSecretChange:
			return verifySecretChange(log, &state, entry)
		case OpSecretRemove:
			return verifySecretRemove(log, &state, entry)
		default:
			return fmt.Errorf("unexpected core.Operation: %#v", entry.Operation)
		}
	})
	if err != nil {
		return nil, err
	}

	// TODO: Is that a hard error? Or should we just warn here?
	// Could be that sesam was legit interrupted during operation.
	if srs := state.SealRequiredSeqID; srs > 0 {
		return nil, fmt.Errorf("entry %d required a seal, but none was made afer", srs)
	}

	return &state, nil
}
