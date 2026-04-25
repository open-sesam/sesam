package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/renameio"
	"github.com/google/uuid"
)

const (
	sesamInitialHashSeed = "sesam.init"
)

// Operation specifies what operation a specific entry describes.
// It is unlikely you need to use this directly.
type operation string

const (
	opInit         = operation("init")
	opUserTell     = operation("user.tell")
	opUserKill     = operation("user.kill")
	opSecretChange = operation("secret.change")
	opSecretRemove = operation("secret.remove")
	opSeal         = operation("seal")
)

// AuditDetail is a type constraint covering all valid detail types.
type AuditDetail interface {
	DetailInit |
		DetailUserTell |
		DetailUserKill |
		DetailSecretChange |
		DetailSecretRemove |
		DetailSeal
}

type auditEntry struct {
	// Operation describes the operation that happened.
	// See above for a full list.
	Operation operation `json:"operation"`

	// ChangedBy is the user that executed the operation.
	ChangedBy string `json:"changed_by"`

	// Detail are operation specific details.
	Detail            json.RawMessage `json:"detail"`
	unmarshaledDetail any

	// SeqID is a monontonically increasing. First entry is 1.
	SeqID uint64 `json:"seq_id"`

	// PreviousHash is the hash of the json-encoded previous entry.
	// The hash algorithm is encoded via multihash in the hash itself.
	// It also includes the signature of the previous entry.
	PreviousHash string `json:"previous_hash"`

	// Time is when this operation happened (ISO8601, UTC)
	Time time.Time `json:"time"`
}

// AuditEntrySigned contains a regular AuditEntry but includes the signature based on it.
type auditEntrySigned struct {
	auditEntry

	// Signature is a signature made by the user in `ChangedBy` of this entry.
	//
	// Signature includes all fields of AuditEntry (encoded as canonical json)
	// Signed by the user that executed the operation.
	//
	// Since an entry also contains a link to the previous entry we indirectly also
	// sign all previous entries.
	Signature string `json:"signature"`
}

///////// DETAILS /////////////

// DetailInit is added on init.
//
// It is the base of audit log and establishes the first admin user.
// The embedded Admin field pins the initial admin's signing pubkey
// to the trust anchor (.sesam/audit/init), preventing log truncation
// attacks: Eve cannot forge a new init entry with herself as admin
// without rewriting git history.
//
// Verification:
//
// - SeqID must be 1.
// - The hash at .sesam/audit/init must be the same as the hash of this entry (including signature).
// - Admin must have valid keys and include the "admin" group.
// - ChangedBy must match Admin.User.
type DetailInit struct {
	// This is uniquely generated per repo.
	// It has no specific purpose beyond debugging
	// and as input for the initial hash.
	InitUUID string `json:"init_uuid"`

	// Admin is the initial admin user established at repo creation.
	// This pins the admin's signing pubkey to the trust anchor.
	Admin DetailUserTell `json:"admin"`
}

// DetailUserTell describes a newly added user.
//
// Verification:
//
//   - The ChangedBy user must be an admin user.
//   - A user may not add himself.
//   - The user may not exist already.
//   - Adding users should always be followed by a seal in the log (not a hard error, but a warning).
//   - The seal has to result in a different root hash than before (to make sure files really were changed).
//   - PubKeys and SignPubKeys must be valid keys.
//   - Groups may not have duplicates.
//
// The initial admin is established via DetailInit, not via a separate user.tell entry.
//
// Note:
//
// - If a user is changed (different key e.g.) then this is handled as remove and add.
// - The log contains only the security relevant aspects.
type DetailUserTell struct {
	// User to add.
	User string `json:"user"`

	// Groups the user should be added to.
	Groups []string `json:"group"`

	// PubKeys of that user over time.
	PubKeys []string `json:"pub_key"`

	// SignPubKeys of that user.
	// This should most likely just be one,
	// but due to key-rotation it might be in theory several.
	SignPubKeys []string `json:"sign_pub_key"`
}

// DetailUserKill describes the operation of removing a user from the repo.
//
// Verification:
//
// - ChangedBy user must be an admin.
// - The user may not be the last "admin" user in the repo.
// - A seal with different RootHash has to follow after this.
type DetailUserKill struct {
	User string `json:"user"`
}

// DetailSecretChange describes the operation of adding/changing a secret.
//
// Verification:
//
// - "admin" may be part of `Groups`, but is implicitly added anyways.
// - `Groups` may not be empty.
// - `Groups` should not have duplicates.
// - If secret exists: Only users that already have access to it may issue another Change.
//
// Note:
//
// - When changing the access list it is okay to issue another SecretMod
type DetailSecretChange struct {
	RevealedPath string   `json:"revealed_path"`
	Groups       []string `json:"groups"`
}

// DetailSecretRemove is the act of removing a secret.
//
// Verification:
//
//   - Only users with access to this secret may remove it.
//     (User still could remove it from disk/git though...)
type DetailSecretRemove struct {
	RevealedPath string `json:"revealed_path"`
}

// DetailSeal is the operation of sealing all files.
//
// Verification:
//
// - RootHash is the hash of all encrypted files (sorted by path before hash).
//
// Note:
//
// - FilesSealed is purely informative.
type DetailSeal struct {
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
//     => For this we write .sesam/audit/init - the hash of the initial log entry.
//     => This hash is then compared to the init of current audit log.
//     => If it matches, we can assume the log did not get truncated.
//     => For added safety, we can also check if .sesam/audit/init was never changed via git.
//     => If no .git/ repo is there we should not just have a hard dependency but print a warning.
//     => This is also the reason why we should not allow git push --force, as this might be used to rewrite history.
//
// In all cases verify would complain about it and warn an user about Eve.
type AuditLog struct {
	Entries []auditEntrySigned `json:"entries"`

	// SesamDir is the dir in which .sesam resides.
	SesamDir string `json:"-"`

	// The hash from the .sesam/audit/init file.
	// It should be the same hash as the prev_hash of the 2nd entry.
	InitHash string `json:"-"`

	// file descriptor for adding new entries.
	fd *os.File
}

// operationFor returns the operation type for a given detail struct.
func operationFor(detail any) operation {
	switch detail.(type) {
	case *DetailInit:
		return opInit
	case *DetailUserTell:
		return opUserTell
	case *DetailUserKill:
		return opUserKill
	case *DetailSecretChange:
		return opSecretChange
	case *DetailSecretRemove:
		return opSecretRemove
	case *DetailSeal:
		return opSeal
	default:
		panic(fmt.Sprintf("unknown detail type: %T", detail))
	}
}

// NewAuditEntry creates a new entry with compile-time type safety on the detail.
// The operation is derived from the detail type.
// SeqID, PreviousHash and Time are filled by AuditLog.AddEntry().
func newAuditEntry[T AuditDetail](changedBy string, detail *T) *auditEntry {
	detailJSON, _ := json.Marshal(detail)
	return &auditEntry{
		Operation:         operationFor(detail),
		ChangedBy:         changedBy,
		Time:              time.Now().UTC(),
		Detail:            detailJSON,
		unmarshaledDetail: detail,
	}
}

// ParseDetail unmarshals the detail into the given type.
// The result is cached so repeated calls don't re-unmarshal.
func parseDetail[T AuditDetail](e *auditEntrySigned) (*T, error) {
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

// Hash computes the current hash of the entry when all fields (including signature) are set.
func (aes *auditEntrySigned) Hash() string {
	// include signature:
	sigJSON, _ := json.Marshal(aes)
	return hashData(sigJSON)
}

func (aes *auditEntrySigned) String() string {
	sigJSON, _ := json.MarshalIndent(aes, "", "  ")
	return string(sigJSON)
}

func (aes *auditEntrySigned) Verify(kr Keyring) (string, error) {
	// do not include signature:
	wholeEntryJSON, err := json.Marshal(aes.auditEntry)
	if err != nil {
		return "", err
	}

	return kr.Verify(SesamDomainSignAuditTag, wholeEntryJSON, aes.Signature, aes.ChangedBy)
}

// InitAuditLog initializes an empty audit log on repo init.
// It creates the first init entry which also establishes the initial admin user.
func InitAuditLog(sesamDir string, signer Signer, admin DetailUserTell) (*AuditLog, error) {
	logPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")

	if err := os.MkdirAll(filepath.Dir(initPath), 0o700); err != nil {
		return nil, err
	}

	//nolint:gosec
	fd, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_SYNC|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}

	al := &AuditLog{
		SesamDir: sesamDir,
		fd:       fd,
	}

	initEntry := newAuditEntry(signer.UserName(), &DetailInit{
		InitUUID: uuid.New().String(),
		Admin:    admin,
	})

	signedEntry, err := al.AddEntry(signer, initEntry, nil)
	if err != nil {
		closeLogged(al.fd)
		return nil, fmt.Errorf("failed to init log: %w", err)
	}

	initHash := signedEntry.Hash()
	if err := renameio.WriteFile(
		initPath,
		[]byte(initHash),
		0o600,
	); err != nil {
		closeLogged(al.fd)
		return nil, fmt.Errorf("failed to write init file: %w", err)
	}

	al.InitHash = initHash
	return al, nil
}

func (al *AuditLog) Close() error {
	return al.fd.Close()
}

// AddEntry will add another signed entry to the audit log.
// This action is non-reversible, not even via code - make sure that the data added is correct!
//
// The `verify` function is called before append the log to the file on disk, use this to make
// sure that the log verifies as correctly by calling state.Update().
func (al *AuditLog) AddEntry(signer Signer, e *auditEntry, verify func() error) (*auditEntrySigned, error) {
	entry := &auditEntrySigned{
		auditEntry: *e,
	}

	entry.SeqID = uint64(len(al.Entries)) + 1

	if len(al.Entries) > 0 {
		// Compute hash of previous entry:
		entry.PreviousHash = al.Entries[len(al.Entries)-1].Hash()
	} else {
		// use a fixed hash, just so we don't have to deal with that value being sometimes empty.
		entry.PreviousHash = hashData([]byte(sesamInitialHashSeed))
	}

	// build signature of now complete entry:
	wholeEntryJSON, err := json.Marshal(entry.auditEntry)
	if err != nil {
		return nil, fmt.Errorf("marshal current entry: %w", err)
	}

	entry.Signature, err = signer.Sign(SesamDomainSignAuditTag, wholeEntryJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to sign entry: %w", err)
	}

	al.Entries = append(al.Entries, *entry)

	if verify != nil {
		if err := verify(); err != nil {
			al.Entries = al.Entries[:len(al.Entries)-1] // pop failed entry off.
			return entry, err
		}
	}

	// We encode it twice just for one different entry, which is a bit wastelful...
	sigJSON, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	sigJSON = append(sigJSON, '\n')
	if _, err := al.fd.Write(sigJSON); err != nil {
		return nil, err
	}

	if err := al.fd.Sync(); err != nil {
		return nil, err
	}

	return entry, nil
}

func (al *AuditLog) Iterate(fn func(idx int, entry *auditEntrySigned) error) error {
	for idx := 0; idx < len(al.Entries); idx++ {
		if err := fn(idx, &al.Entries[idx]); err != nil {
			return err
		}
	}

	return nil
}

// LoadAuditLog reads the audit log from disk and gives you an handle to operate on it.
// It does NOT verify the log yet. Call Verify() for that.
func LoadAuditLog(sesamDir string) (*AuditLog, error) {
	logPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")

	initData, err := readFileLimited(initPath, 256)
	if err != nil {
		return nil, err
	}

	al := AuditLog{
		SesamDir: sesamDir,
		InitHash: strings.TrimSpace(string(initData)),
	}

	//nolint:gosec
	al.fd, err = os.OpenFile(logPath, os.O_APPEND|os.O_SYNC|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}

	info, err := al.fd.Stat()
	if err != nil {
		closeLogged(al.fd)
		return nil, err
	}

	// Reject audit logs bigger than 512M.
	// In some later release we need to figure a way
	// to compress such large logs if that ever becomes a problem.
	if info.Size() > 512*1024*1024 {
		closeLogged(al.fd)
		return nil, fmt.Errorf("audit log too big (> 512M). Please consider opening a bug report")
	}

	lineNumber := 1
	dec := json.NewDecoder(al.fd)
	for dec.More() {
		var entry auditEntrySigned
		if err := dec.Decode(&entry); err != nil {
			// A partial trailing entry means we were interrupted mid-write.
			// Truncate back to the last good entry and continue — the incomplete
			// entry never finished and can be safely discarded.
			goodOffset := dec.InputOffset()
			slog.Warn(
				"audit log has incomplete trailing entry (interrupted write?), truncating",
				slog.Int("line", lineNumber),
				slog.Int64("truncate_at", goodOffset),
			)

			if err := al.fd.Truncate(goodOffset); err != nil {
				closeLogged(al.fd)
				return nil, fmt.Errorf("failed to truncate corrupt trailing entry: %w", err)
			}

			break
		}

		al.Entries = append(al.Entries, entry)
		lineNumber++
	}

	// Seek to end so subsequent writes append after the last good entry.
	if _, err := al.fd.Seek(0, io.SeekEnd); err != nil {
		closeLogged(al.fd)
		return nil, fmt.Errorf("failed to seek to end: %w", err)
	}

	return &al, nil
}

// BuildRootHash will produce a combined hash ("Root Hash") out of all
// hashes of encrypted files. It serves as general integrity protection
// (a bit similar like a merkle tree, just not with hierarchy)
//
// Side effect: This will sort `sigs`
func buildRootHash(sigs []*secretSignature) string {
	sort.Slice(sigs, func(i, j int) bool {
		return sigs[i].RevealedPath < sigs[j].RevealedPath
	})

	b := bytes.NewBuffer(nil)
	for _, sig := range sigs {
		b.WriteString(sig.Hash)
		b.WriteByte('\n')
	}

	return hashData(b.Bytes())
}
