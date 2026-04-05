package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/renameio"
)

type Operation string

const (
	OpInit             = Operation("init")
	OpUserTell         = Operation("user.tell")
	OpUserKill         = Operation("user.kill")
	OpGroupJoin        = Operation("group.join")
	OpGroupLeave       = Operation("group.leave")
	OpAccessListChange = Operation("access.change")
	OpSeal             = Operation("seal")
)

// AuditDetail is a type constraint covering all valid detail types.
type AuditDetail interface {
	AuditEntryInit |
		AuditEntryUserTell | AuditEntryUserKill |
		AuditEntryGroupJoin | AuditEntryGroupLeave |
		AuditEntryAccessListChange | AuditEntrySeal
}

type AuditEntry struct {
	// Operation describes the operation that happened.
	// See above for a full list.
	Operation Operation `json:"operation"`

	// ChangedBy is the user that executed the operation.
	ChangedBy string `json:"changed_by"`

	// Detail are operation specific details.
	Detail            json.RawMessage `json:"detail"`
	unmarshaledDetail any             `json:"-"`

	// SeqID is a monontonically increasing. First entry is 1.
	SeqID uint64 `json:"seq_id"`

	// PreviousHash is the hash of the json-encoded previous entry.
	// The hash algorithm is encoded via multihash in the hash itself.
	// It also includes the signature of the previous entry.
	PreviousHash string `json:"previous_hash"`

	// Time is when this operation happened (ISO8601, UTC)
	Time time.Time `json:"time"`
}

// NewAuditEntry creates a new entry with compile-time type safety on the detail.
// SeqID, PreviousHash and Time are filled by AuditLog.AddEntry().
func NewAuditEntry[T AuditDetail](op Operation, changedBy string, detail *T) (*AuditEntry, error) {
	raw, err := json.Marshal(detail)
	if err != nil {
		return nil, fmt.Errorf("marshal detail: %w", err)
	}

	return &AuditEntry{
		Operation:         op,
		ChangedBy:         changedBy,
		Detail:            raw,
		unmarshaledDetail: detail,
	}, nil
}

// ParseDetail unmarshals the detail into the given type.
// The result is cached so repeated calls don't re-unmarshal.
func ParseDetail[T AuditDetail](e *AuditEntry) (*T, error) {
	if e.unmarshaledDetail != nil {
		if d, ok := e.unmarshaledDetail.(*T); ok {
			return d, nil
		}

		return nil, fmt.Errorf("entry %d: detail is %T, not *%T", e.SeqID, e.unmarshaledDetail, *new(T))
	}

	var d T
	if err := json.Unmarshal(e.Detail, &d); err != nil {
		return nil, fmt.Errorf("unmarshal detail for seq %d: %w", e.SeqID, err)
	}

	e.unmarshaledDetail = &d
	return &d, nil
}

type AuditEntrySigned struct {
	AuditEntry

	// Signature is a signature made by the user in `ChangedBy` of this entry.
	//
	// Signature includes all fields of AuditEntry (encoded as canonical json)
	// Signed by the user that executed the operation.
	//
	// Since an entry also contains a link to the previous entry we indirectly also
	// sign all previous entries.
	Signature string `json:"signature"`
}

type AuditEntryInit struct {
	// none currently, just added for consistency.
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
	User string `json:"user"`

	// TODO: Reference the user struct of config here?

	// PubKeys of that user over time.
	PubKey     []string `json:"pub_key"`
	SignPubKey string   `json:"sign_pub_key"`

	// Signature of above fields to avoid self-add.
	CounterSignature string `json:"counter_signature"`
}

// AuditEntryUserKill describes the operation of removing a user from the repo.
//
// Verification:
//
// - The user may not be the last user in the repo.
// - The user may not be the last "admin" user in the repo.
// - A seal with different RootHash should follow after this.
type AuditEntryUserKill struct {
	User string `json:"user"`

	// Signature of above fields to avoid self-add
	CounterSignature string `json:"counter_signature"`
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
	User             string `json:"user"`
	Group            string `json:"group"`
	CounterSignature string `json:"counter_signature"`
}

type AuditEntryGroupLeave struct {
	User             string `json:"user"`
	Group            string `json:"group"`
	CounterSignature string `json:"counter_signature"`
}

type AuditEntryAccessListChange struct {
	RevealedPath     string   `json:"revealed_path"`
	Groups           []string `json:"groups"`
	CounterSignature string   `json:"counter_signature"`
}

type AuditEntrySeal struct {
	// This hash is build from the sorted list of all .sig.json files after seal.
	RootHash string `json:"root_hash"`

	// FilesSealed is the number of files that were sealed.
	FilesSealed int `json:"files_sealed"`
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
	Entries []AuditEntrySigned `json:"entries"`

	// RepoDir is the dir in which .sesam resides.
	RepoDir string `json:"-"`

	// Signer needed to add new entries and verify old ones.
	Signer Signer `json:"-"`
}

func EmptyLog(repoDir string, signer Signer) (*AuditLog, error) {
	al := &AuditLog{
		RepoDir: repoDir,
		Signer:  signer,
	}

	// TODO: We need to pass the user here...?
	if err := al.AddEntry(OpInit, "sahib", AuditEntryInit{}); err != nil {
		return nil, fmt.Errorf("failed to init log: %w", err)
	}

	return al, nil
}

func (al *AuditLog) AddEntry(op Operation, changedBy string, detail any) error {
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("marshal detail: %w", err)
	}

	entry := &AuditEntrySigned{
		AuditEntry: AuditEntry{
			Operation:         op,
			ChangedBy:         changedBy,
			Detail:            detailJSON,
			unmarshaledDetail: detail,
			SeqID:             uint64(len(al.Entries)) + 1,
			Time:              time.Now().UTC(),
		},
	}

	if len(al.Entries) > 0 {
		// Compute hash of previous entry:
		prev := al.Entries[len(al.Entries)-1]
		prevJSON, err := json.Marshal(prev)
		if err != nil {
			return fmt.Errorf("marshal previous entry: %w", err)
		}

		entry.PreviousHash = Hash(prevJSON)
	} else {
		// use a fixed hash, just so we don't have to deal with that value being sometimes empty.
		entry.PreviousHash = Hash([]byte("init"))
	}

	// build signature of now complete entry:
	wholeEntryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal current entry: %w", err)
	}

	entry.Signature, err = al.Signer.Sign(wholeEntryJSON)
	if err != nil {
		return fmt.Errorf("failed to sign entry: %w", err)
	}

	al.Entries = append(al.Entries, *entry)
	return nil
}

func (al *AuditLog) Iterate(fn func(entry *AuditEntrySigned) error) error {
	for idx := 0; idx < len(al.Entries); idx++ {
		// entry := &al.Entries[idx]
		// if entry.unmarshaledDetail == nil && len(entry.Detail) > 0 {
		// 	entry.unmarshaledDetail = nil
		// }

		// TODO: lazy load detail here?
		if err := fn(&al.Entries[idx]); err != nil {
			return err
		}
	}

	return nil
}

func (al *AuditLog) Store() error {
	// TODO: implement chunking at some point; for now just one big log.
	logPath := filepath.Join(al.RepoDir, ".sesam", "audit", fmt.Sprintf("%06d.log", 0))
	fd, err := renameio.TempFile(al.RepoDir, logPath)
	if err != nil {
		return err
	}

	defer fd.Cleanup()

	enc := json.NewEncoder(fd)
	enc.SetIndent("", "  ")
	if err := enc.Encode(al); err != nil {
		return fmt.Errorf("marshal entries: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	return fd.CloseAtomicallyReplace()
}

func LoadAuditLog(repoDir string, signer Signer) (*AuditLog, error) {
	// TODO: also implement chunking for loading.
	logPath := filepath.Join(repoDir, ".sesam", "audit", fmt.Sprintf("%06d.log", 0))
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return EmptyLog(repoDir, signer)
	}

	fd, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}

	defer fd.Close()

	al := AuditLog{
		RepoDir: repoDir,
		Signer:  signer,
	}

	dec := json.NewDecoder(fd)
	if err := dec.Decode(&al); err != nil {
		return nil, err
	}

	return &al, nil
}
