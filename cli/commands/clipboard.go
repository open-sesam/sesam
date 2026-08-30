package commands

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gopasspw/clipboard"
	"github.com/sahib/renameio/v2"
	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/argon2"
)

const (
	envClipboardCopyCmd  = "SESAM_CLIPBOARD_COPY_CMD"
	envClipboardPasteCmd = "SESAM_CLIPBOARD_PASTE_CMD"
)

// argon2id parameters for the clipboard digest. They are deliberately on the
// cheap side (~50ms): the digest only has to survive as long as the secret is
// on the clipboard, and it is derived once per `sesam show --clip`.
const (
	clipHashTime    = 1
	clipHashMemory  = 64 * 1024 // KiB
	clipHashThreads = 4
	clipHashKeyLen  = 32
	clipHashSaltLen = 16
	clipHashScheme  = "argon2id"
)

// clipboardBackend is the slice of clipboard access sesam needs. The
// indirection exists so SESAM_CLIPBOARD_COPY_CMD / SESAM_CLIPBOARD_PASTE_CMD
// can stand in for the system clipboard on setups the library does not cover
// - and so the testscripts can run without a display server.
type clipboardBackend interface {
	Write(ctx context.Context, content []byte) error
	Read(ctx context.Context) ([]byte, error)
}

// systemClipboard talks to the display server via gopasspw/clipboard.
type systemClipboard struct{}

// commandClipboard pipes through user-supplied shell commands: the copy
// command receives the content on stdin, the paste command prints it.
type commandClipboard struct {
	copyCmd  string
	pasteCmd string
}

// unclipState is handed from `sesam show --clip` to the detached `sesam
// unclip` child through a file in the user's runtime dir. It carries a digest
// rather than the secret, so the plaintext stays in exactly one process.
type unclipState struct {
	// Token identifies the copy that wrote this state. A child whose token
	// no longer matches has been superseded and must not touch the clipboard.
	Token string `json:"token"`
	// Digest is the argon2id hash of the copied content.
	Digest string `json:"digest"`
}

func (systemClipboard) Write(ctx context.Context, content []byte) error {
	// WritePassword tags the content with a password-manager hint where the
	// backend supports it (wl-copy's MIME type, the macOS ConcealedType), so
	// clipboard managers can skip storing it. Backends that reject the hint
	// fall back to a plain write - a copy that works beats one that hides.
	err := clipboard.WritePassword(ctx, content)
	if err == nil {
		return nil
	}

	slog.Debug("clipboard: password hint unsupported, writing plain", slog.Any("error", err))
	return clipboard.WriteAll(ctx, content)
}

func (systemClipboard) Read(ctx context.Context) ([]byte, error) {
	return clipboard.ReadAll(ctx)
}

func (c commandClipboard) Write(ctx context.Context, content []byte) error {
	//nolint:gosec // the command is the user's own env override
	cmd := exec.CommandContext(ctx, "sh", "-c", c.copyCmd)
	cmd.Stdin = bytes.NewReader(content)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", envClipboardCopyCmd, err)
	}

	return nil
}

func (c commandClipboard) Read(ctx context.Context) ([]byte, error) {
	//nolint:gosec // the command is the user's own env override
	cmd := exec.CommandContext(ctx, "sh", "-c", c.pasteCmd)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envClipboardPasteCmd, err)
	}

	return out, nil
}

// newClipboardBackend picks the command backend when both env overrides are
// set and the system clipboard otherwise.
func newClipboardBackend() (clipboardBackend, error) {
	copyCmd := os.Getenv(envClipboardCopyCmd)
	pasteCmd := os.Getenv(envClipboardPasteCmd)

	switch {
	case copyCmd != "" && pasteCmd != "":
		return commandClipboard{copyCmd: copyCmd, pasteCmd: pasteCmd}, nil
	case copyCmd != "" || pasteCmd != "":
		return nil, fmt.Errorf("%s and %s must be set together", envClipboardCopyCmd, envClipboardPasteCmd)
	case clipboard.IsUnsupported():
		return nil, fmt.Errorf(
			"no clipboard available: install xclip, xsel or wl-clipboard, or set %s and %s",
			envClipboardCopyCmd, envClipboardPasteCmd,
		)
	}

	return systemClipboard{}, nil
}

// copyToClipboard puts the shown object on the clipboard and arms the
// automatic clear. With wait it stays in the foreground until the ttl expires
// (or the user interrupts); otherwise it starts a detached `sesam unclip`
// that outlives this process.
func copyToClipboard(ctx context.Context, content []byte, wait bool, ttl time.Duration) error {
	// Secret files end in a newline more often than not, and a trailing
	// newline turns a pasted password into a submitted form.
	content = bytes.TrimRight(content, "\n")
	if len(content) == 0 {
		return fmt.Errorf("refusing to copy empty content to the clipboard")
	}

	cb, err := newClipboardBackend()
	if err != nil {
		return err
	}

	if err := cb.Write(ctx, content); err != nil {
		return fmt.Errorf("copy to clipboard failed: %w", err)
	}

	if ttl <= 0 {
		slog.Warn("clipboard will not be cleared automatically", slog.String("reason", "--ttl is 0"))
		return nil
	}

	if !wait {
		return spawnUnclip(content, ttl)
	}

	slog.Info("waiting for clipboard to expire", slog.Duration("ttl", ttl))

	var interrupted error
	select {
	case <-ctx.Done():
		interrupted = ctx.Err()
	case <-time.After(ttl):
	}

	// A Ctrl+C during the wait must still wipe the clipboard, so the clear
	// runs on a context that outlives the cancellation.
	matches := func(cur []byte) bool {
		return subtle.ConstantTimeCompare(cur, content) == 1
	}
	if err := clearClipboard(context.WithoutCancel(ctx), cb, matches); err != nil {
		return err
	}

	return interrupted
}

// clearClipboard wipes the clipboard, but only if it still holds what we put
// there. Whatever the user copied in the meantime is left alone.
func clearClipboard(ctx context.Context, cb clipboardBackend, matches func([]byte) bool) error {
	cur, err := cb.Read(ctx)
	if err != nil {
		return fmt.Errorf("read clipboard: %w", err)
	}

	if !matches(bytes.TrimRight(cur, "\n")) {
		slog.Info("clipboard changed since it was copied, leaving it alone")
		return nil
	}

	if err := cb.Write(ctx, nil); err != nil {
		return fmt.Errorf("clear clipboard: %w", err)
	}

	slog.Info("clipboard cleared")
	return nil
}

// spawnUnclip records a digest of the copied content and starts a detached
// `sesam unclip` that clears the clipboard once the ttl is up.
func spawnUnclip(content []byte, ttl time.Duration) error {
	digest, err := hashClipboard(content)
	if err != nil {
		return err
	}

	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("generate clipboard token: %w", err)
	}
	token := hex.EncodeToString(raw)

	statePath, err := unclipStatePath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(statePath), err)
	}

	state, err := json.Marshal(unclipState{Token: token, Digest: digest})
	if err != nil {
		return err
	}

	if err := renameio.WriteFile(statePath, state, 0o600); err != nil {
		return fmt.Errorf("write unclip state: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate sesam binary: %w", err)
	}

	// Background, not the caller's context: the child has to survive this
	// process exiting, which is the whole point of detaching it.
	//nolint:gosec // re-exec of our own binary
	child := exec.CommandContext(context.Background(), exe, "unclip", "--ttl", ttl.String(), "--token", token)
	child.SysProcAttr = detachedProcAttr()
	// `show` doubles as git's textconv driver, so nothing it spawns may write
	// to our stdio - and a log line arriving in the terminal a minute later
	// would be noise anyway.
	child.Stdin, child.Stdout, child.Stderr = nil, nil, nil

	if err := child.Start(); err != nil {
		return fmt.Errorf("start unclip: %w", err)
	}

	pid := child.Process.Pid
	// Nothing ever waits for the child; releasing it hands it to init.
	if err := child.Process.Release(); err != nil {
		slog.Debug("release unclip child failed", slog.Any("error", err))
	}

	slog.Info("clipboard will be cleared", slog.Duration("ttl", ttl), slog.Int("pid", pid))
	return nil
}

// HandleUnclip is the detached companion of `sesam show --clip`: it waits out
// the TTL and then clears the clipboard, provided it still holds the copied
// secret and no newer copy has superseded this one.
func HandleUnclip(ctx context.Context, cmd *cli.Command) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(cmd.Duration("ttl")):
	}

	statePath, err := unclipStatePath()
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(statePath) //nolint:gosec // path derived from the runtime dir
	if err != nil {
		if os.IsNotExist(err) {
			slog.Debug("no clipboard state on disk, nothing to clear")
			return nil
		}
		return fmt.Errorf("read unclip state: %w", err)
	}

	var state unclipState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("parse unclip state: %w", err)
	}

	// A later `show --clip` took ownership of the clipboard and armed its own
	// timer. Clearing here would cut that TTL short - most visibly when the
	// same secret is copied twice, where the digest would still match.
	if subtle.ConstantTimeCompare([]byte(state.Token), []byte(cmd.String("token"))) != 1 {
		slog.Debug("superseded by a newer clipboard copy")
		return nil
	}

	cb, err := newClipboardBackend()
	if err != nil {
		return err
	}

	matches := func(cur []byte) bool {
		ok, err := matchClipboard(cur, state.Digest)
		if err != nil {
			slog.Warn("cannot verify clipboard content", slog.Any("error", err))
			return false
		}
		return ok
	}
	if err := clearClipboard(ctx, cb, matches); err != nil {
		return err
	}

	if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		slog.Warn("cannot remove unclip state", slog.Any("error", err))
	}

	return nil
}

// hashClipboard derives an argon2id digest of the clipboard content. The
// detached child gets this instead of the secret, so the plaintext is never
// duplicated into a second process that may outlive the terminal.
func hashClipboard(content []byte) (string, error) {
	salt := make([]byte, clipHashSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey(content, salt, clipHashTime, clipHashMemory, clipHashThreads, clipHashKeyLen)
	return fmt.Sprintf(
		"%s$%d$%d$%d$%s$%s",
		clipHashScheme, clipHashTime, clipHashMemory, clipHashThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// matchClipboard reports whether content hashes to the given digest.
func matchClipboard(content []byte, digest string) (bool, error) {
	parts := strings.Split(digest, "$")
	if len(parts) != 6 || parts[0] != clipHashScheme {
		return false, fmt.Errorf("malformed clipboard digest")
	}

	// TODO: Are you sure there's no beter way to 
	timeCost, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return false, fmt.Errorf("clipboard digest time: %w", err)
	}
	memory, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return false, fmt.Errorf("clipboard digest memory: %w", err)
	}
	threads, err := strconv.ParseUint(parts[3], 10, 8)
	if err != nil {
		return false, fmt.Errorf("clipboard digest threads: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("clipboard digest salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("clipboard digest key: %w", err)
	}
	if len(want) == 0 || len(want) > 64 {
		return false, fmt.Errorf("clipboard digest key size out of range: %d", len(want))
	}

	//nolint:gosec // G115: len(want) is bounded to 64 above
	got := argon2.IDKey(content, salt, uint32(timeCost), uint32(memory), uint8(threads), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// unclipStatePath is the per-user handover file between `show --clip` and its
// unclip child. It lives in the runtime dir so it disappears on logout. The
// path is only computed here - the child must never create anything.
func unclipStatePath() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("locate cache dir: %w", err)
		}
		base = cacheDir
	}

	return filepath.Join(base, "sesam", "unclip.json"), nil
}
