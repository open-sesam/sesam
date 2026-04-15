package core

import (
	"bytes"
	"encoding/json"
	"fmt"
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

type Operation string

const (
	OpInit         = Operation("init")
	OpUserTell     = Operation("user.tell")
	OpUserKill     = Operation("user.kill")
	OpSecretChange = Operation("secret.change")
	OpSecretRemove = Operation("secret.remove")
	OpSeal         = Operation("seal")
)

// AuditDetail is a type constraint covering all valid detail types.
type AuditDetail interface {
	DetailInit |
		DetailUserTell | DetailUserKill |
		DetailSecretChange | DetailSecretRemove |
		DetailSeal
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

// TODO: Derive `op` from detail type?
// NewAuditEntry creates a new entry with compile-time type safety on the detail.
// SeqID, PreviousHash and Time are filled by AuditLog.AddEntry().
func NewAuditEntry[T AuditDetail](op Operation, changedBy string, detail *T) *AuditEntry {
	detailJSON, _ := json.Marshal(detail)
	return &AuditEntry{
		Operation:         op,
		ChangedBy:         changedBy,
		Time:              time.Now().UTC(),
		Detail:            detailJSON,
		unmarshaledDetail: detail,
	}
}

// ParseDetail unmarshals the detail into the given type.
// The result is cached so repeated calls don't re-unmarshal.
func ParseDetail[T AuditDetail](e *AuditEntrySigned) (*T, error) {
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

// Hash computes the current hash of the entry when all fields (including signature) are set.
func (aes *AuditEntrySigned) Hash() string {
	// include signature:
	sigJSON, _ := json.Marshal(aes)
	return Hash(sigJSON)
}

func (aes *AuditEntrySigned) String() string {
	sigJSON, _ := json.MarshalIndent(aes, "", "  ")
	return string(sigJSON)
}

func (aes *AuditEntrySigned) Verify(kr Keyring) (string, error) {
	// do not include signature:
	wholeEntryJSON, err := json.Marshal(aes.AuditEntry)
	if err != nil {
		return "", err
	}

	return kr.Verify(wholeEntryJSON, aes.Signature, aes.ChangedBy)
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
//
// TODO: What if changing the only user in the repo? (i.e. add a new pub key)
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
	// NOTE: We should chunk the log to make life for git easier and avoid loading too big files at once:
	//
	// .sesam/audit/
	// 			00000.log.json
	// 			00100.log.json // rotate every 100 entries.
	// 			00200.log.json // rotate every 100 entries.
	Entries []AuditEntrySigned `json:"entries"`

	// RepoDir is the dir in which .sesam resides.
	RepoDir string `json:"-"`

	// Signer needed to add new entries
	Signer Signer `json:"-"`

	// The hash from the .sesam/audit/init file.
	// It should be the same hash as the prev_hash of the 2nd entry.
	InitHash string `json:"-"`

	// Keyring contains all known public keys
	Keyring Keyring `json:"-"`
}

// EmptyLog initializes an empty audit log on repo init.
// It creates the first init entry which also establishes the initial admin user.
func EmptyLog(repoDir string, signer Signer, kr Keyring, admin DetailUserTell) (*AuditLog, error) {
	al := &AuditLog{
		RepoDir: repoDir,
		Signer:  signer,
		Keyring: kr,
	}

	initEntry := NewAuditEntry(OpInit, signer.UserName(), &DetailInit{
		InitUUID: uuid.New().String(),
		Admin:    admin,
	})

	signedEntry, err := al.AddEntry(initEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to init log: %w", err)
	}

	initPath := filepath.Join(repoDir, ".sesam", "audit", "init")
	_ = os.MkdirAll(filepath.Dir(initPath), 0700)

	initHash := signedEntry.Hash()
	if err := renameio.WriteFile(
		initPath,
		[]byte(initHash),
		0600,
	); err != nil {
		return nil, fmt.Errorf("failed to write init file: %w", err)
	}

	al.InitHash = initHash
	return al, nil
}

// AddEntry will add another signed entry to the audit log.
// This action is non-reversible, not even via code.
func (al *AuditLog) AddEntry(e *AuditEntry) (*AuditEntrySigned, error) {
	entry := &AuditEntrySigned{
		AuditEntry: *e,
	}

	entry.SeqID = uint64(len(al.Entries)) + 1

	if len(al.Entries) > 0 {
		// Compute hash of previous entry:
		entry.PreviousHash = al.Entries[len(al.Entries)-1].Hash()
	} else {
		// use a fixed hash, just so we don't have to deal with that value being sometimes empty.
		entry.PreviousHash = Hash([]byte(sesamInitialHashSeed))
	}

	// build signature of now complete entry:
	wholeEntryJSON, err := json.Marshal(entry.AuditEntry)
	if err != nil {
		return nil, fmt.Errorf("marshal current entry: %w", err)
	}

	entry.Signature, err = al.Signer.Sign(wholeEntryJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to sign entry: %w", err)
	}

	al.Entries = append(al.Entries, *entry)

	// TODO: We should automatically verify the new entry to make sure verified-state is up-to-date.
	return entry, nil
}

func (al *AuditLog) Iterate(fn func(idx int, entry *AuditEntrySigned) error) error {
	for idx := 0; idx < len(al.Entries); idx++ {
		if err := fn(idx, &al.Entries[idx]); err != nil {
			return err
		}
	}

	return nil
}

func (al *AuditLog) Store() error {
	logPath := filepath.Join(al.RepoDir, ".sesam", "audit", "log.json")
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

// LoadAuditLog reads the audit log from disk and gives you an handle to operate on it.
// It does NOT verify the log yet.
func LoadAuditLog(repoDir string, signer Signer, kr Keyring) (*AuditLog, error) {
	logPath := filepath.Join(repoDir, ".sesam", "audit", "log.json")
	initPath := filepath.Join(repoDir, ".sesam", "audit", "init")
	initData, err := os.ReadFile(initPath)
	if err != nil {
		return nil, err
	}

	fd, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}

	defer closeLogged(fd)

	al := AuditLog{
		RepoDir:  repoDir,
		Signer:   signer,
		InitHash: strings.TrimSpace(string(initData)),
		Keyring:  kr,
	}

	dec := json.NewDecoder(fd)
	if err := dec.Decode(&al); err != nil {
		return nil, err
	}

	return &al, nil
}

// BuildRootHash will produce a combined hash ("Root Hash") out of all
// hashes of encrypted files. It serves as general integrity protection
// (a bit similar like a merkle tree, just not with hierarchy)
//
// TODO: Pass in all sealed files in here? What about partial seals?
func BuildRootHash(sigs []*SecretSignature) string {
	sort.Slice(sigs, func(i, j int) bool {
		return sigs[i].RevealedPath < sigs[j].RevealedPath
	})

	b := bytes.NewBuffer(nil)
	for _, sig := range sigs {
		b.WriteString(sig.Hash)
		b.WriteByte('\n')
	}

	return Hash(b.Bytes())
}
