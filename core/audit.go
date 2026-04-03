package core

import (
	"encoding/json"
	"fmt"
	"time"
)

type Operation string

const (
	OpUserTell         = Operation("user.tell")
	OpUserKill         = Operation("user.kill")
	OpGroupJoin        = Operation("group.join")
	OpGroupLeave       = Operation("group.leave")
	OpAccessListChange = Operation("access.change")
	OpSeal             = Operation("seal")
)

type AuditEntry struct {
	// Operation describes the operation that happened.
	// See above for a full list.
	Operation Operation `json:"operation"`

	// SeqID is a monontonically increasing. First entry is 1.
	SeqID uint64 `json:"seq_id"`

	// PreviousHash is the hash of the json-encoded previous entry.
	// The hash algorithm is encoded via multihash in the hash itself.
	PreviousHash string `json:"hash"`

	// Time is when this operation happened (ISO8601, UTC)
	Time time.Time `json:"time"`

	// ChangeBy is the user that executed the operation.
	ChangedBy string `json:"changed_by"`

	// Detail are operation specific details.
	Detail            json.RawMessage `json:"detail"`
	unmarshaledDetail any             `json:"-"`
}

func (ae *AuditEntry) SetDetail(d any) {
	ae.unmarshaledDetail = d
}

// GetDetail returns the detail
// (Sorry, you have )
func (ae *AuditEntry) GetDetail() any {
	return ae.unmarshaledDetail
}

type AuditEntrySigned struct {
	AuditEntry

	// Signature includes all fields of AuditEntry (encoded as canonical json)
	// Signed by the user that executed the operation.
	Signature string `json:"signature"`
}

// AuditEntryUserTell describes a newly added user.
//
// Verification:
//
// - A add may never be followed by an add of the same user.
// - Adding a user should always be followed by a seal.
// - The seal should result in a different RootHash than before.
// - The ChangedBy user has to be an admin user.
// - A user tell may only be done by an init user.
// - Only if SeqID is 1 (inital user) we allow that a user signs itself.
//
// Note:
//
// - If a user is changed (different key e.g.) then this counts as add and remove.
type AuditEntryUserTell struct {
	// User to add
	User string

	// TODO: Reference the user struct of config here?

	// PubKeys of that user over time.
	PubKey     []string
	SignPubKey string

	// Signature of above fields to avoid self-add.
	CounterSignature string
}

// AuditEntryUserKill describes the operation of removing a user from the repo.
//
// Verification:
//
// - The user may not be the last user in the repo.
// - The user may not be the last "admin" user in the repo.
// - A seal with different RootHash should follow after this.
type AuditEntryUserKill struct {
	User string

	// Signature of above fields to avoid self-add
	CounterSignature string
}

// AuditEntryGroupJoin describes the operation of adding a user to a group.
//
// Verification:
//
// - The ChangedBy user has to be an admin.
// - A seal of all files should follow closely after this.
//
// Note:
//
// - Joining the "admin" group is also done using this.
type AuditEntryGroupJoin struct {
	User             string
	Group            string
	CounterSignature string
}

type AuditEntryGroupLeave struct {
	User             string
	Group            string
	CounterSignature string
}

type AuditEntryAccessListChange struct {
	RevealedPath     string
	Groups           []string
	CounterSignature string
}

type AuditEntrySeal struct {
	// This hash is build from the sorted list of all .sig.json files after seal.
	RootHash string

	// FilesSealed is the number of files that were sealed.
	FilesSealed int
}

// AuditLog records all operations that change the state of the sesam repo.
// It is an append-only log that cannot be rewritten.
//
// We require this audit log for two use cases:
//
// 1. Letting the user audit what has happened in the past (i.e. reading logs)
// 2. Authenticating every change of users, groups and access lists.
//
// The first use case is probably self explanatory.
// Use case 2 needs some explanation. Consider the following example.
//
//  1. Eve is a regular user that has no admin rights, but can push to the git repo.
//  2. Eve could just write herself into sesam.yml as new admin.
//  3. Eve could even replace all encrypted files with ones she controls optionally.
//     (she can't decrypt serets she had no prior access to, but she could try substitute them)
//  3. Eve could then push those changes to a remote and hope another user would re-encrypt the files for
//     her so that she now has admin access to all of them.
//
// This attack vector should be protected by the audit log.
// Eve has three options:
//
//  1. Eve does not add something to the audit log:
//     => verify can reconstruct the user/group/access and would notice that the state in sesam.yml is not the expected state.
//  2. Eve adds according entries to the audit log:
//     => Adding a user requires the signature of an existing admin.
//     => verify would therefore notice a self-signed signature.
//  3. Eve truncates the log and rebuilds it to her liking:
//     => verify needs to check that the log in the previous commit had the same initial root.
//
// In all cases verify would complain about it and warn an user about Eve.
type AuditLog struct {
	// NOTE: We should chunk the log to make life for git easier and avoid loading too big files at once:
	//
	// .sesam/audit/
	// 			00000.log.json
	// 			00100.log.json // rotate every 100 entries.
	// 			00200.log.json // rotate every 100 entries.
	Entries []AuditEntry
}

func (al *AuditLog) AddEntry(entry *AuditEntry) error {
	data, err := json.Marshal(entry.unmarshaledDetail)
	if err != nil {
		return fmt.Errorf("failed to marshal details: %w", err)
	}

	entry.Detail = data

	// TODO: Build signature and marshal the whole thing.
	return nil
}

func (al *AuditLog) Iterate(fn func(entry *AuditEntry) error) error {
	// TODO: xxx
	return nil
}

func (al *AuditLog) Store() error {
	// TODO: xxx
	return nil
}

func LoadAuditLog(path string) (*AuditLog, error) {
	// TODO: xxx
	return nil, nil
}
