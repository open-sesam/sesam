package repo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/index"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/google/renameio"
	"github.com/open-sesam/sesam/core"
)

// FilterProcessHandler decrypts blobs as part of the long-running git filter
// protocol. Identities, Keyring and Authorize are loaded by the caller
// before Run is invoked, so key/passphrase work and audit-log parsing are
// amortised across all blobs in a single git operation - and so a session
// can never silently degrade to "no auth check" because of a missing audit
// log: the caller's LoadAuditView decides up-front whether to proceed.
//
// The sesamDir is derived per-blob from the pathname header (see
// splitObjectPath) so the handler also works when .sesam lives in a
// worktree subdirectory.
//
// IdentityPaths lists the key files loaded as Identities. Any path that
// points inside the worktree is excluded from Cleanup so users who store
// their age key inside the repo don't lose it on checkout.
type FilterProcessHandler struct {
	// SesamDir is the directory containing `.sesam/` (resolved via
	// clirepo.ResolveSesamDir from --sesam-dir / SESAM_DIR). The same
	// path drives audit-log loading, working-tree cleanup, and the
	// destination for revealed plaintext.
	SesamDir string

	Identities    core.Identities
	IdentityPaths []string

	// Keyring is used by reveal to verify the ed25519 signature on the
	// sealed file footer. Loaded by the caller via LoadAuditView so the
	// filter session can fail-fast if the audit log can't be read,
	// rather than silently skipping the check per-blob.
	Keyring core.Keyring

	// Authorize reports whether the user named in the sealed file
	// footer is allowed to have sealed revealedPath under the audit
	// log's state at session start. Caller-supplied (alongside Keyring)
	// for the same fail-fast reason.
	Authorize func(user, revealedPath string) bool

	cleaned bool
}

// objectsSegment and sesamSuffix bracket the encrypted-blob path that git
// passes via the `pathname` header (long-running) or %f (one-shot). We treat
// `.sesam/objects/` as a substring rather than a strict prefix so the path
// also resolves correctly when the .sesam directory is nested inside the
// worktree (git always passes the path relative to the worktree root, and
// the prefix before `.sesam/objects/` is the sesamDir).
const (
	objectsSegment = ".sesam/objects/"
	sesamSuffix    = ".sesam"
)

// errProtocol marks a violation of the pkt-line filter protocol. Reaching this
// state means the conversation with git is no longer recoverable, so the
// process must exit.
var errProtocol = errors.New("filter protocol violation")

// RunFilterProcess speaks git's long-running filter protocol on stdin/stdout.
// See `man 5 gitattributes` and https://git-scm.com/docs/gitprotocol-common.
//
// The protocol is symmetric pkt-line: a handshake, capability negotiation,
// then a request/response loop that runs until git closes stdin. We advertise
// only the `smudge` capability - clean is identity for sesam (the working-tree
// blob stays encrypted) so git falls back to the legacy `clean = cat` config.
func (h *FilterProcessHandler) Run(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	scanner := pktline.NewScanner(stdin)
	encoder := pktline.NewEncoder(stdout)

	if err := handshake(scanner, encoder); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	if err := negotiateCapabilities(scanner, encoder); err != nil {
		return fmt.Errorf("capability negotiation: %w", err)
	}

	for ctx.Err() == nil {
		headers, ok, err := readHeaders(scanner)
		if err != nil {
			return fmt.Errorf("read headers: %w", err)
		}
		if !ok {
			// Clean EOF between requests means git closed stdin.
			return nil
		}

		if headers["command"] != "smudge" {
			// We only advertised `smudge`, so anything else is a protocol
			// violation. Tell git via status=error and bail - no point draining
			// the content stream when we are about to exit anyway.
			msg := fmt.Sprintf("unsupported command %q", headers["command"])
			_ = writeStatusError(encoder, msg)
			return fmt.Errorf("%w: %s", errProtocol, msg)
		}

		if err := h.handleSmudgeRequest(scanner, encoder, headers["pathname"]); err != nil {
			return err
		}
	}

	return ctx.Err()
}

// splitObjectPath splits a worktree-relative encrypted-object pathname into
// (sesamDir, revealedPath). Returns ok=false if pathname does not contain
// the .sesam/objects/ segment or does not end with .sesam.
//
// The first occurrence of `.sesam/objects/` is the boundary - if a revealed
// path itself happens to contain `.sesam/objects/`, the outer segment still
// wins, which matches every realistic layout.
//
// Examples:
//
//	.sesam/objects/secrets/token.sesam        -> (".",       "secrets/token", true)
//	subdir/.sesam/objects/secrets/token.sesam -> ("subdir",  "secrets/token", true)
//	outside/path.txt                          -> ("",        "",              false)
func splitObjectPath(pathname string) (sesamDir, revealedPath string, ok bool) {
	if !strings.HasSuffix(pathname, sesamSuffix) {
		return "", "", false
	}
	idx := strings.Index(pathname, objectsSegment)
	if idx < 0 {
		return "", "", false
	}
	sesamDir = strings.TrimSuffix(pathname[:idx], "/")
	if sesamDir == "" {
		sesamDir = "."
	}
	revealedPath = strings.TrimSuffix(pathname[idx+len(objectsSegment):], sesamSuffix)
	return sesamDir, revealedPath, true
}

// handshake exchanges the protocol greeting. Git announces itself first; the
// filter must reply with matching version.
func handshake(scanner *pktline.Scanner, encoder *pktline.Encoder) error {
	if err := expectLine(scanner, "git-filter-client"); err != nil {
		return err
	}
	if err := expectLine(scanner, "version=2"); err != nil {
		return err
	}
	if err := expectFlush(scanner); err != nil {
		return err
	}

	if err := encoder.EncodeString("git-filter-server\n"); err != nil {
		return err
	}
	if err := encoder.EncodeString("version=2\n"); err != nil {
		return err
	}
	return encoder.Flush()
}

// negotiateCapabilities advertises only the capabilities sesam actually
// implements. Git treats anything else as the filter being unable to handle
// that operation and falls back to the legacy command (or skips the filter).
func negotiateCapabilities(scanner *pktline.Scanner, encoder *pktline.Encoder) error {
	clientCaps := map[string]bool{}
	for {
		ok, payload, err := nextLine(scanner)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: unexpected EOF during capability negotiation", errProtocol)
		}
		if payload == "" {
			break
		}
		const prefix = "capability="
		if !strings.HasPrefix(payload, prefix) {
			return fmt.Errorf("%w: expected capability=<name>, got %q", errProtocol, payload)
		}
		clientCaps[strings.TrimPrefix(payload, prefix)] = true
	}

	if !clientCaps["smudge"] {
		return fmt.Errorf("%w: client does not offer smudge capability", errProtocol)
	}

	// we only do smudge right now, we might add `git add` later.
	// TODO: Can we change paths when using the clean filter?
	if err := encoder.EncodeString("capability=smudge\n"); err != nil {
		return err
	}
	return encoder.Flush()
}

// readHeaders consumes pkt-lines until a flush, parsing each as `key=value`.
// The boolean return distinguishes the two valid termination cases of the
// outer request loop:
//
//   - ok=true:  flush packet was reached; `headers` is populated and the
//     content stream follows.
//   - ok=false, err=nil: clean EOF on the very first scan. The long-running
//     filter protocol has no explicit end-of-session message; git just
//     closes stdin once there are no more blobs to filter. We surface that
//     as ok=false so the request loop can return nil.
//
// EOF *after* at least one header has been read is a protocol violation:
// git is required to terminate the header block with a flush, so a
// mid-block EOF means the pipe died unexpectedly.
func readHeaders(scanner *pktline.Scanner) (map[string]string, bool, error) {
	headers := map[string]string{}
	for i := 0; ; i++ {
		ok, payload, err := nextLine(scanner)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			if i == 0 {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("%w: EOF in middle of header block", errProtocol)
		}
		if payload == "" {
			return headers, true, nil
		}
		key, value, ok := strings.Cut(payload, "=")
		if !ok {
			return nil, false, fmt.Errorf("%w: malformed header %q", errProtocol, payload)
		}
		headers[key] = value
	}
}

// handleSmudgeRequest streams one smudge request: each input pkt-line is
// echoed straight back as a pkt-line of the same size (so git gets the
// encrypted blob unchanged) and the same bytes are dropped into a spill
// file. No whole-blob memory buffering.
//
// On the first request of a session, stale plaintext from earlier checkouts
// is wiped via Cleanup before any reveal runs. Cleanup failure is logged but
// not fatal - aborting `git checkout` over a half-cleaned tree is worse
// than leaving a few stragglers.
//
// .gitattributes scopes the filter to sesam objects, so a pathname that
// does not match the expected layout is treated as a hard error. Reveal
// failures further along (seek, RevealBlob) are still tolerated with a
// warn log - aborting `git checkout` over one undecryptable file is worse
// than a stale plaintext.
func (h *FilterProcessHandler) handleSmudgeRequest(scanner *pktline.Scanner, encoder *pktline.Encoder, pathname string) error {
	_, revealedPath, isObject := splitObjectPath(pathname)
	if !isObject {
		return fmt.Errorf("not a path sesam smudge can handle: %v", pathname)
	}

	if !h.cleaned {
		h.cleaned = true
		if err := cleanWorktree(h.SesamDir, h.IdentityPaths); err != nil {
			slog.Warn("smudge: cleanup failed", slog.String("err", err.Error()))
		}
	}

	if err := writeStatus(encoder, "success"); err != nil {
		return err
	}

	spill, err := openSpillFile(h.SesamDir)
	if err != nil {
		return err
	}

	defer func() { _ = spill.Cleanup() }()

	// Each Scan() yields one input pkt-line (≤ MaxPayloadSize bytes). We
	// forward it as-is via Encode (one new pkt-line of equal size) and, if
	// we have a spill open, tee it to disk so reveal can read the full blob.
	for {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w: EOF in middle of content", errProtocol)
		}
		chunk := scanner.Bytes()
		if len(chunk) == 0 {
			break // input flush == end of content
		}
		if err := encoder.Encode(chunk); err != nil {
			return err
		}

		if _, err := spill.Write(chunk); err != nil {
			return fmt.Errorf("spill write: %w", err)
		}
	}
	// First flush mirrors end-of-content; second flush is end-of-response
	// (an empty trailing list with no `status=...` packet means success).
	if err := encoder.Flush(); err != nil {
		return err
	}
	if err := encoder.Flush(); err != nil {
		return err
	}

	if _, err := spill.Seek(0, io.SeekStart); err != nil {
		slog.Warn("smudge: failed to seek spill", slog.String("path", pathname), slog.String("err", err.Error()))
		return nil
	}

	revealed, err := core.RevealBlob(
		h.SesamDir,
		h.Identities,
		spill,
		revealedPath,
		h.Keyring,
		h.Authorize,
	)

	var authErr *core.BadSealerError
	switch {
	case errors.As(err, &authErr):
		// The plaintext landed (RevealBlob returns true on auth
		// errors); we just shout into stderr so the user sees the
		// mismatch in their `git checkout` output. Hard-failing
		// would block history bisects of pre-fix commits where the
		// killed-user re-seal never happened.
		slog.Error(
			"smudge: sealer is not in the access list - decrypting anyway, run `sesam verify --all` to confirm intent",
			slog.String("path", pathname),
			slog.String("sealer", authErr.SealedBy),
		)
	case err != nil:
		slog.Warn("smudge: could not reveal", slog.String("path", pathname), slog.String("err", err.Error()))
	case !revealed:
		slog.Debug("smudge: not a recipient, skipping reveal", slog.String("path", pathname))
	}
	return nil
}

// LoadAuditView reads the audit log (preferring the git **index** copy -
// consistent with the target tree even mid-checkout, since git updates the
// index before invoking the filter - and falling back to the working-tree
// copy) and returns the keyring + sealer-authorization predicate the
// smudge filter needs to verify each revealed blob.
//
// Callers must invoke this before constructing FilterProcessHandler so a
// filter session never silently degrades to "no auth check" because the
// audit log was unavailable.
func LoadAuditView(sesamDir string, ids core.Identities) (core.Keyring, func(user, revealedPath string) bool, error) {
	kr, authorize, err := loadAuditViewFromIndex(sesamDir, ids)
	if err == nil {
		return kr, authorize, nil
	}
	slog.Debug(
		"smudge: audit log not loadable from git index; falling back to working tree",
		slog.String("err", err.Error()),
	)

	// Working-tree copy may lag the in-progress checkout (git writes
	// files in unspecified order), but it's the only remaining source
	// when the index lookup is unavailable.
	kr, authorize, wtErr := loadAuditViewFromWorktree(sesamDir, ids)
	if wtErr != nil {
		return nil, nil, fmt.Errorf("load audit view (index and worktree both failed): %w", errors.Join(err, wtErr))
	}
	return kr, authorize, nil
}

func loadAuditViewFromIndex(sesamDir string, ids core.Identities) (core.Keyring, func(user, revealedPath string) bool, error) {
	repo, err := OpenGitRepo(sesamDir)
	if err != nil {
		return nil, nil, fmt.Errorf("open git repo at %q: %w", sesamDir, err)
	}
	idx, err := repo.Storer.Index()
	if err != nil {
		return nil, nil, fmt.Errorf("read git index: %w", err)
	}

	// Index entries are repo-root-relative with forward slashes.
	// sesamDir is the same shape (resolved from --sesam-dir, default
	// "."); path.Join collapses "." correctly when sesam lives at the
	// worktree root.
	auditPath := path.Join(sesamDir, ".sesam/audit/log.jsonl")

	blobIdx := slices.IndexFunc(idx.Entries, func(e *index.Entry) bool {
		return e.Name == auditPath
	})

	if blobIdx < 0 {
		return nil, nil, fmt.Errorf("audit log not in git index at %q", auditPath)
	}

	blobHash := idx.Entries[blobIdx].Hash
	blob, err := repo.BlobObject(blobHash)
	if err != nil {
		return nil, nil, fmt.Errorf("read audit log blob %s: %w", blobHash, err)
	}
	rd, err := blob.Reader()
	if err != nil {
		return nil, nil, fmt.Errorf("open audit log blob: %w", err)
	}
	defer func() { _ = rd.Close() }()

	al, err := core.LoadAuditLogFromReader(rd, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt audit log from index: %w", err)
	}
	kr := core.EmptyKeyring()
	state, err := core.VerifyChain(al, kr)
	if err != nil {
		return nil, nil, fmt.Errorf("verify audit chain (index version): %w", err)
	}
	return kr, state.SealerAuthorized, nil
}

func loadAuditViewFromWorktree(sesamDir string, ids core.Identities) (core.Keyring, func(user, revealedPath string) bool, error) {
	al, err := core.LoadAuditLog(sesamDir, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("load audit log: %w", err)
	}
	kr := core.EmptyKeyring()
	state, err := core.VerifyChain(al, kr)
	if err != nil {
		return nil, nil, fmt.Errorf("verify audit chain: %w", err)
	}
	return kr, state.SealerAuthorized, nil
}

// cleanWorktree removes stale untracked files from sesamDir, excluding the
// given identity file paths. It is called at most once per filter session
// (guarded by FilterProcessHandler.cleaned).
func cleanWorktree(sesamDir string, identityPaths []string) error {
	repo, err := OpenGitRepo(sesamDir)
	if err != nil {
		return err
	}
	return Cleanup(repo, sesamDir, identityPaths...)
}

// openSpillFile creates a scratch file inside sesamDir/.sesam/tmp using
// renameio.TempFile so the temp lives on the same filesystem as the rest
// of the .sesam tree and gets cleaned up with one Cleanup() call. We never
// call CloseAtomicallyReplace - the spill is read back, then discarded.
func openSpillFile(sesamDir string) (*renameio.PendingFile, error) {
	tmpDir := filepath.Join(sesamDir, ".sesam", "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating tmp dir: %w", err)
	}
	f, err := renameio.TempFile(tmpDir, filepath.Join(tmpDir, "smudge"))
	if err != nil {
		return nil, fmt.Errorf("creating spill file: %w", err)
	}
	return f, nil
}

func writeStatus(encoder *pktline.Encoder, status string) error {
	if err := encoder.EncodeString("status=" + status + "\n"); err != nil {
		return err
	}
	return encoder.Flush()
}

func writeStatusError(encoder *pktline.Encoder, msg string) error {
	slog.Warn("smudge: protocol error", slog.String("err", msg))
	if err := writeStatus(encoder, "error"); err != nil {
		return err
	}
	// Trailing flush closes the response.
	return encoder.Flush()
}

// nextLine advances the scanner once. Returns (false, "", nil) on clean EOF,
// or the payload (with any trailing newline stripped) on success. A flush is
// reported as ok=true with payload="".
func nextLine(scanner *pktline.Scanner) (bool, string, error) {
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, "", err
		}
		return false, "", nil
	}
	return true, strings.TrimRight(string(scanner.Bytes()), "\n"), nil
}

func expectLine(scanner *pktline.Scanner, want string) error {
	ok, payload, err := nextLine(scanner)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: expected %q, got EOF", errProtocol, want)
	}
	if payload != want {
		return fmt.Errorf("%w: expected %q, got %q", errProtocol, want, payload)
	}
	return nil
}

func expectFlush(scanner *pktline.Scanner) error {
	ok, payload, err := nextLine(scanner)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: expected flush, got EOF", errProtocol)
	}
	if payload != "" {
		return fmt.Errorf("%w: expected flush, got %q", errProtocol, payload)
	}
	return nil
}
