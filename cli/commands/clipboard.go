package commands

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gopasspw/clipboard"
	shellquote "github.com/kballard/go-shellquote"
	"github.com/sahib/renameio/v2"
	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/argon2"
)

// The clipboard flow:
//
//	show --clip  copies the secret, writes {token, digest} to the runtime dir
//	             and starts a detached `sesam unclip` (or waits itself, with -w).
//	unclip       bails out if it was already superseded, sleeps out the TTL,
//	             then clears - but only if the clipboard still holds the digest.
//
// The child gets the digest, never the secret, so the plaintext stays in one
// process. The token is what lets a newer copy supersede an older timer, which
// matters when the same secret is copied twice and the digest alone would match.

const (
	flagClipboardCopyCmd  = "clipboard-copy-cmd"
	flagClipboardPasteCmd = "clipboard-paste-cmd"
)

// argon2id parameters for the clipboard digest, tuned to ~25ms: it is derived
// once per `sesam show --clip`, on the path between populating the clipboard
// and handing the shell back, so it is felt directly.
const (
	clipHashTime    = 1
	clipHashMemory  = 48 * 1024 // KiB
	clipHashThreads = 4
	clipHashKeyLen  = 32
	clipHashSaltLen = 16
)

// clipboardBackend is the slice of clipboard access sesam needs. The
// indirection exists so --clipboard-copy-cmd / --clipboard-paste-cmd can stand
// in for the system clipboard on setups the library does not cover - and so the
// testscripts can run without a display server.
type clipboardBackend interface {
	Write(ctx context.Context, content []byte) error
	Read(ctx context.Context) ([]byte, error)
}

// systemClipboard talks to the display server via gopasspw/clipboard.
type systemClipboard struct{}

// commandClipboard pipes through user-supplied commands: the copy command
// receives the content on stdin, the paste command prints it. Both are split
// with sh word rules but executed directly, so no shell sees the secret.
type commandClipboard struct {
	copyCmd  []string
	pasteCmd []string
}

// clipboardOpts are the clipboard settings the handlers parse off the command
// line, so the plumbing below never touches flags itself.
type clipboardOpts struct {
	clip     bool
	alsoClip bool
	copyCmd  string
	pasteCmd string
	ttl      time.Duration
	wait     bool
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
	// Password clipboard works only in darwin.
	// gopass avoids it on Linux for the same reason.
	if runtime.GOOS != "darwin" {
		return clipboard.WriteAll(ctx, content)
	}

	err := clipboard.WritePassword(ctx, content)
	if err == nil {
		return nil
	}

	slog.Debug("clipboard: password hint failed, writing plain", slog.Any("error", err))
	return clipboard.WriteAll(ctx, content)
}

func (systemClipboard) Read(ctx context.Context) ([]byte, error) {
	return clipboard.ReadAll(ctx)
}

func (c commandClipboard) Write(ctx context.Context, content []byte) error {
	//nolint:gosec // the command is the user's own
	cmd := exec.CommandContext(ctx, c.copyCmd[0], c.copyCmd[1:]...)
	cmd.Stdin = bytes.NewReader(content)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("--%s: %w", flagClipboardCopyCmd, err)
	}

	return nil
}

func (c commandClipboard) Read(ctx context.Context) ([]byte, error) {
	//nolint:gosec // the command is the user's own
	cmd := exec.CommandContext(ctx, c.pasteCmd[0], c.pasteCmd[1:]...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flagClipboardPasteCmd, err)
	}

	return out, nil
}

// clipboardOptsFrom reads the clipboard settings off the command line.
//
// The show flags are declared twice - on `show`, and hidden on the root so the
// pass-style `sesam -c <path>` parses at all. A value given before the
// subcommand name therefore lands on the root and the local flag keeps its
// default, so take whichever side was actually given.
func clipboardOptsFrom(cmd *cli.Command) clipboardOpts {
	given := func(name string) *cli.Command {
		if !cmd.IsSet(name) && cmd.Root().IsSet(name) {
			return cmd.Root()
		}

		return cmd
	}

	return clipboardOpts{
		clip:     given("clip").Bool("clip"),
		alsoClip: given("alsoclip").Bool("alsoclip"),
		copyCmd:  cmd.String(flagClipboardCopyCmd),
		pasteCmd: cmd.String(flagClipboardPasteCmd),
		ttl:      given("ttl").Duration("ttl"),
		wait:     given("wait").Bool("wait"),
	}
}

// flagGiven reports whether a flag was passed at all, on either side of the
// subcommand name. See clipboardOptsFrom for why that is two places.
func flagGiven(cmd *cli.Command, name string) bool {
	return cmd.IsSet(name) || cmd.Root().IsSet(name)
}

// newClipboardBackend picks the command backend when both overrides are set
// and the system clipboard otherwise.
func newClipboardBackend(ctx context.Context, copyCmd, pasteCmd string) (clipboardBackend, error) {
	switch {
	case copyCmd != "" && pasteCmd != "":
		copyArgs, err := splitClipboardCmd(flagClipboardCopyCmd, copyCmd)
		if err != nil {
			return nil, err
		}

		pasteArgs, err := splitClipboardCmd(flagClipboardPasteCmd, pasteCmd)
		if err != nil {
			return nil, err
		}

		return commandClipboard{copyCmd: copyArgs, pasteCmd: pasteArgs}, nil
	case copyCmd != "" || pasteCmd != "":
		return nil, fmt.Errorf("--%s and --%s must be set together", flagClipboardCopyCmd, flagClipboardPasteCmd)
	case clipboard.IsUnsupported():
		// Which helper binaries count, and what to install, is knowledge that
		// belongs to gopasspw/clipboard - so ask it for the message instead of
		// keeping a second copy in sync here. With no backend available ReadAll
		// fails before it touches anything, so this stays side-effect free.
		_, err := clipboard.ReadAll(ctx)
		if err == nil {
			err = errors.New("no clipboard utilities available")
		}

		return nil, fmt.Errorf("%w; alternatively set --%s and --%s", err, flagClipboardCopyCmd, flagClipboardPasteCmd)
	}

	return systemClipboard{}, nil
}

// splitClipboardCmd applies sh word-splitting so `--clipboard-copy-cmd "xclip
// -selection clipboard"` works, without handing the secret to a shell.
func splitClipboardCmd(flag, cmd string) ([]string, error) {
	args, err := shellquote.Split(cmd)
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flag, err)
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("--%s is empty", flag)
	}

	return args, nil
}

// copyToClipboard puts the shown object on the clipboard and arms the
// automatic clear. With wait it stays in the foreground until the ttl expires
// (or the user interrupts); otherwise it starts a detached `sesam unclip`
// that outlives this process.
func copyToClipboard(ctx context.Context, content []byte, opts clipboardOpts) error {
	// Secret files end in a newline more often than not, and a trailing
	// newline turns a pasted password into a submitted form.
	content = bytes.TrimRight(content, "\n")
	if len(content) == 0 {
		return fmt.Errorf("refusing to copy empty content to the clipboard")
	}

	cb, err := newClipboardBackend(ctx, opts.copyCmd, opts.pasteCmd)
	if err != nil {
		return err
	}

	if err := cb.Write(ctx, content); err != nil {
		return fmt.Errorf("copy to clipboard failed: %w", err)
	}

	if opts.ttl <= 0 {
		slog.Warn("clipboard will not be cleared automatically (--ttl 0)")
		return nil
	}

	if !opts.wait {
		return spawnUnclip(content, opts.ttl)
	}

	slog.Info("waiting for clipboard to expire", slog.Duration("ttl", opts.ttl))

	var ctxErr error
	select {
	case <-ctx.Done():
		ctxErr = ctx.Err()
	case <-time.After(opts.ttl):
	}

	// A Ctrl+C during the wait must still wipe the clipboard, so the clear
	// runs on a context that outlives the cancellation.
	matches := func(cur []byte) bool {
		return subtle.ConstantTimeCompare(cur, content) == 1
	}
	if err := clearClipboard(context.WithoutCancel(ctx), cb, matches); err != nil {
		return err
	}

	return ctxErr
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
	digest := hashClipboard(content)

	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("generate clipboard token: %w", err)
	}
	token := hex.EncodeToString(raw)

	statePath := unclipStatePath()
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
	opts := clipboardOptsFrom(cmd)
	token := cmd.String("token")

	// Everything that can be decided without the clipboard is decided now:
	// holding a process for the whole TTL only to find there is nothing to do
	// is wasteful, and a broken clipboard config should say so immediately.
	if _, ok, err := loadUnclipState(token); err != nil || !ok {
		return err
	}

	cb, err := newClipboardBackend(ctx, opts.copyCmd, opts.pasteCmd)
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(opts.ttl):
	}

	// Re-read rather than trust the check above: a `show --clip` during the
	// sleep takes ownership of the clipboard and arms its own timer, and this
	// one must not cut that TTL short.
	state, ok, err := loadUnclipState(token)
	if err != nil || !ok {
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

	// A crashed unclip leaving this behind blocks nothing: every copy replaces
	// the file atomically, and a stale token can only ever make a later child
	// decide it has no work.
	if err := os.Remove(unclipStatePath()); err != nil && !os.IsNotExist(err) {
		slog.Warn("cannot remove unclip state", slog.Any("error", err))
	}

	return nil
}

// loadUnclipState reads the handover file and reports whether token still owns
// the clipboard. A missing file or a newer token both mean: not our job.
func loadUnclipState(token string) (unclipState, bool, error) {
	raw, err := os.ReadFile(unclipStatePath())
	if err != nil {
		if os.IsNotExist(err) {
			slog.Debug("no clipboard state on disk, nothing to clear")
			return unclipState{}, false, nil
		}

		return unclipState{}, false, fmt.Errorf("read unclip state: %w", err)
	}

	var state unclipState
	if err := json.Unmarshal(raw, &state); err != nil {
		return unclipState{}, false, fmt.Errorf("parse unclip state: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(state.Token), []byte(token)) != 1 {
		slog.Debug("superseded by a newer clipboard copy")
		return unclipState{}, false, nil
	}

	return state, true, nil
}

// hashClipboard derives an argon2id digest of the clipboard content. The
// detached child gets this instead of the secret, so the plaintext is never
// duplicated into a second process that may outlive the terminal.
//
// The encoding is just salt||key: the parameters are the constants above, and
// nothing outside this binary ever reads a digest, so there is nothing to
// negotiate and no format to parse.
func hashClipboard(content []byte) string {
	digest := make([]byte, clipHashSaltLen, clipHashSaltLen+clipHashKeyLen)
	salt := digest
	if _, err := rand.Read(salt); err != nil {
		// crypto/rand.Read never fails on any platform sesam supports; a
		// system that broke it cannot be trusted to hold a secret either.
		panic("crypto/rand failed: " + err.Error())
	}

	key := argon2.IDKey(content, salt, clipHashTime, clipHashMemory, clipHashThreads, clipHashKeyLen)
	return base64.RawStdEncoding.EncodeToString(append(digest, key...))
}

// matchClipboard reports whether content hashes to the given digest.
func matchClipboard(content []byte, digest string) (bool, error) {
	raw, err := base64.RawStdEncoding.DecodeString(digest)
	if err != nil {
		return false, fmt.Errorf("decode clipboard digest: %w", err)
	}

	if len(raw) != clipHashSaltLen+clipHashKeyLen {
		return false, fmt.Errorf("clipboard digest is %d bytes, want %d", len(raw), clipHashSaltLen+clipHashKeyLen)
	}

	salt, want := raw[:clipHashSaltLen], raw[clipHashSaltLen:]
	got := argon2.IDKey(content, salt, clipHashTime, clipHashMemory, clipHashThreads, clipHashKeyLen)

	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func unclipStatePath() string {
	// Not os.UserCacheDir: that is persistent storage, and a digest of a live
	// secret has no business outliving the session. XDG_RUNTIME_DIR is per-user,
	// 0700 and cleared at logout; /tmp is shared, so scope the fallback by uid.
	if base := os.Getenv("XDG_RUNTIME_DIR"); base != "" {
		return filepath.Join(base, "sesam", "unclip.json")
	}

	return filepath.Join(os.TempDir(), fmt.Sprintf("sesam-%d", os.Getuid()), "unclip.json")
}
