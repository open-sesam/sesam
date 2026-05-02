package core

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/google/renameio"
	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
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

func (ae *auditEntry) Sign(signer Signer) (*auditEntrySigned, error) {
	wholeEntryJSON, err := json.Marshal(ae)
	if err != nil {
		return nil, fmt.Errorf("marshal current entry: %w", err)
	}

	aes := &auditEntrySigned{
		auditEntry: *ae,
	}

	aes.Signature, err = signer.Sign(SesamDomainSignAuditTag, wholeEntryJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to sign entry: %w", err)
	}

	return aes, nil
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

// Encrypt encrypts the json representation of `aes` using `aead` and then base64 encodes it.
// The resulting data will include a newline
func (aes *auditEntrySigned) Encrypt(aead cipher.AEAD) ([]byte, error) {
	sigJSON, err := json.Marshal(aes)
	if err != nil {
		return nil, fmt.Errorf("marshal signed entry: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint64(nonce, aes.SeqID)
	encData := aead.Seal(nil, nonce, sigJSON, nil)

	base64Buf := make([]byte, base64.RawStdEncoding.EncodedLen(len(encData))+1)
	base64.RawStdEncoding.Encode(base64Buf, encData)
	base64Buf[len(base64Buf)-1] = '\n'
	return base64Buf, nil
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
	// This hash is build from the sorted list of all signature footers after seal.
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
	Entries []auditEntrySigned

	// SesamDir is the dir in which .sesam resides.
	SesamDir string

	// The hash from the .sesam/audit/init file.
	// It should be the same hash as the prev_hash of the 2nd entry.
	InitHash string

	// file descriptor for adding new entries.
	fd *os.File

	// encryption support:
	key  [32]byte
	aead cipher.AEAD

	closed bool
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

// WriteAuditKey rewrites key.age on disk with all `recps` having access.
// If the file exists already then it is replaced atomically.
func (al *AuditLog) WriteAuditKey(recps Recipients) error {
	keyPath := filepath.Join(al.SesamDir, ".sesam", "audit", "key.age")
	return al.writeAuditKey(recps, keyPath, al.key[:])
}

func (al *AuditLog) writeAuditKey(recps Recipients, keyPath string, keyBytes []byte) error {
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, recps.AgeRecipients()...)
	if err != nil {
		return fmt.Errorf("encrypt audit key for recipients: %w", err)
	}

	if _, err := w.Write(keyBytes); err != nil {
		return fmt.Errorf("write wrapped audit key: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("finalize age stream: %w", err)
	}

	if err := renameio.WriteFile(keyPath, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("persist audit key file %q: %w", keyPath, err)
	}

	return nil
}

func (al *AuditLog) RotateKey(signer Signer, recps Recipients) error {
	newKey := make([]byte, chacha20poly1305.KeySize)
	rand.Read(newKey)

	newAead, err := chacha20poly1305.New(newKey)
	if err != nil {
		return fmt.Errorf("init aead with new key: %w", err)
	}

	tmpLogPath := filepath.Join(al.SesamDir, ".sesam", "audit", "log.jsonl.tmp")

	//nolint:gosec
	fd, err := os.OpenFile(tmpLogPath, os.O_CREATE|os.O_TRUNC|os.O_SYNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open tmp audit log: %w", err)
	}

	for idx := range al.Entries {
		b64EntryData, err := al.Entries[idx].Encrypt(newAead)
		if err != nil {
			_ = fd.Close()
			return fmt.Errorf("re-encrypt entry %d: %w", idx, err)
		}

		if _, err := fd.Write(b64EntryData); err != nil {
			_ = fd.Close()
			return fmt.Errorf("write entry %d to tmp log: %w", idx, err)
		}
	}

	if err := fd.Sync(); err != nil {
		_ = fd.Close()
		return fmt.Errorf("sync tmp audit log: %w", err)
	}

	if err := fd.Close(); err != nil {
		return fmt.Errorf("close tmp audit log: %w", err)
	}

	// write the updated key to a .tmp file. Note: we deliberately wrap newKey
	// here, not al.key — al.key is still the old key and will only be swapped
	// in once both renames have committed.
	keyPath := filepath.Join(al.SesamDir, ".sesam", "audit", "key.age")
	tmpKeyPath := keyPath + ".tmp"
	if err := al.writeAuditKey(recps, tmpKeyPath, newKey); err != nil {
		return fmt.Errorf("write tmp audit key: %w", err)
	}

	// Now rename both. Note that we might get interrutped between the two renames.
	// If that is the case we rely on the next LoadAuditLog() to realize this and
	// fix this.
	logPath := filepath.Join(al.SesamDir, ".sesam", "audit", "log.jsonl")
	if err := os.Rename(tmpLogPath, logPath); err != nil {
		_ = al.Close()
		return fmt.Errorf("swap rotated log into place: %w", err)
	}

	if err := os.Rename(tmpKeyPath, keyPath); err != nil {
		_ = al.Close()
		return fmt.Errorf("swap rotated key into place: %w", err)
	}

	//nolint:gosec
	newFd, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_SYNC|os.O_RDWR, 0o600)
	if err != nil {
		_ = al.Close()
		return fmt.Errorf("reopen rotated audit log: %w", err)
	}

	// Update aead so we can continue working:
	copy(al.key[:], newKey)
	al.aead = newAead
	_ = al.fd.Close()
	al.fd = newFd
	return nil
}

// ensureRekeyTmpFiles only exists of Rekey() was interrupted between renames.
func ensureRekeyTmpFiles(sesamDir string) error {
	keyPath := filepath.Join(sesamDir, ".sesam", "audit", "key.age")
	tmpKeyPath := keyPath + ".tmp"

	logPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	tmpLogPath := logPath + ".tmp"

	var tmpKeyExists bool
	if _, err := os.Stat(tmpKeyPath); err == nil {
		tmpKeyExists = true
	}

	var tmpLogExists bool
	if _, err := os.Stat(tmpLogPath); err == nil {
		tmpLogExists = true
	}

	if !tmpKeyExists && !tmpLogExists {
		// all good, no interrutped rename.
		return nil
	}

	if !tmpLogExists && tmpKeyExists {
		// most likely interrupted rename.
		// log was likely already written, so assume we should go and use the fitting key.
		slog.Warn("found tmp audit key, will rename to actual key")
		if err := os.Rename(tmpKeyPath, keyPath); err != nil {
			return fmt.Errorf("complete interrupted rotation: %w", err)
		}
		return nil
	}

	if tmpLogExists && !tmpKeyExists {
		// key was never writtten, needs a Rekey()
		// will be likely done when the user retries the operation.
		slog.Warn("found tmp log but no tmp key")
	} else {
		slog.Warn("found rekey in progress, deleting tmp state for safe retry")
	}

	// both tmp file exist, remove them. We will likely retry the Rekey()
	_ = os.Remove(tmpKeyPath)
	_ = os.Remove(tmpLogPath)
	return nil
}

// InitAuditLog initializes an empty audit log on repo init.
// It creates the first init entry which also establishes the initial admin user.
func InitAuditLog(sesamDir string, signer Signer, recps Recipients, admin DetailUserTell) (*AuditLog, error) {
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

	// generate new audit log key and write it to disk:
	rand.Read(al.key[:])
	if err := al.WriteAuditKey(recps); err != nil {
		return nil, err
	}

	al.aead, err = chacha20poly1305.New(al.key[:])
	if err != nil {
		return nil, err
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
	if al.closed {
		return nil
	}

	// attempt to kill the security relevant memory:
	al.aead = nil
	al.key = [32]byte{}
	al.closed = true
	return al.fd.Close()
}

// AddEntry will add another signed entry to the audit log.
// This action is non-reversible, not even via code - make sure that the data added is correct!
//
// The `verify` function is called before append the log to the file on disk, use this to make
// sure that the log verifies as correctly by calling state.Update().
func (al *AuditLog) AddEntry(signer Signer, e *auditEntry, verify func() error) (*auditEntrySigned, error) {
	if al.closed {
		return nil, os.ErrClosed
	}

	e.SeqID = uint64(len(al.Entries)) + 1

	if len(al.Entries) > 0 {
		// Compute hash of previous entry:
		e.PreviousHash = al.Entries[len(al.Entries)-1].Hash()
	} else {
		// use a fixed hash, just so we don't have to deal with that value being sometimes empty.
		e.PreviousHash = hashData([]byte(sesamInitialHashSeed))
	}

	aes, err := e.Sign(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign entry: %w", err)
	}

	al.Entries = append(al.Entries, *aes)

	if verify != nil {
		if err := verify(); err != nil {
			slog.Warn("verify failed - revert last entry", slog.Any("entry", aes), slog.Any("err", err))
			al.Entries = al.Entries[:len(al.Entries)-1] // pop failed entry off.
			return aes, err
		}
	}

	b64EntryData, err := aes.Encrypt(al.aead)
	if err != nil {
		return nil, fmt.Errorf("encrypt entry: %w", err)
	}

	if _, err := al.fd.Write(b64EntryData); err != nil {
		return nil, fmt.Errorf("append entry to log: %w", err)
	}

	if err := al.fd.Sync(); err != nil {
		return nil, fmt.Errorf("sync audit log: %w", err)
	}

	return aes, nil
}

func (al *AuditLog) Iterate(fn func(idx int, entry *auditEntrySigned) error) error {
	if al.closed {
		return os.ErrClosed
	}

	for idx := 0; idx < len(al.Entries); idx++ {
		if err := fn(idx, &al.Entries[idx]); err != nil {
			return err
		}
	}

	return nil
}

func loadAuditKey(path string, ids Identities) ([]byte, error) {
	data, err := ReadFileLimited(path, 1024*1024)
	if err != nil {
		return nil, fmt.Errorf("read audit key file: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(data), ids.AgeIdentities()...)
	if err != nil {
		return nil, fmt.Errorf("decrypt audit key (no matching identity?): %w", err)
	}

	key, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read decrypted audit key: %w", err)
	}

	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("audit key is not %d byte", chacha20poly1305.KeySize)
	}

	return key, nil
}

// LoadAuditLog reads the audit log from disk and gives you an handle to operate on it.
// It does NOT verify the log yet. Call Verify() for that.
func LoadAuditLog(sesamDir string, ids Identities) (*AuditLog, error) {
	if err := ensureRekeyTmpFiles(sesamDir); err != nil {
		return nil, fmt.Errorf("recover from interrupted rotation: %w", err)
	}

	logPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	keyPath := filepath.Join(sesamDir, ".sesam", "audit", "key.age")
	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")

	key, err := loadAuditKey(keyPath, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit key: %w", err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize chacha20poly1305: %w", err)
	}

	initData, err := ReadFileLimited(initPath, 256)
	if err != nil {
		return nil, err
	}

	al := AuditLog{
		SesamDir: sesamDir,
		InitHash: strings.TrimSpace(string(initData)),
		aead:     aead,
	}

	copy(al.key[:], key)

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
	lineBuf := make([]byte, 16*1024)
	scanner := bufio.NewScanner(al.fd)
	for scanner.Scan() {
		base64Entry := scanner.Text()
		encEntryData, err := base64.RawStdEncoding.DecodeString(base64Entry)
		if err != nil {
			closeLogged(al.fd)
			return nil, fmt.Errorf("base64 decode line %d: %w", lineNumber, err)
		}

		nonce := make([]byte, aead.NonceSize())
		binary.BigEndian.PutUint64(nonce, uint64(lineNumber))
		jsonData, err := aead.Open(lineBuf[:0], nonce, encEntryData, nil)
		if err != nil {
			closeLogged(al.fd)
			return nil, fmt.Errorf("decrypt line %d: %w", lineNumber, err)
		}

		var entry auditEntrySigned
		if err := json.Unmarshal(jsonData, &entry); err != nil {
			closeLogged(al.fd)
			return nil, fmt.Errorf("failed to unmarshal line %d: %w", lineNumber, err)
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
