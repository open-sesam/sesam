package core

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age/plugin"
	"golang.org/x/term"
)

// ErrNoTTY is returned by PluginUI callbacks when sesam runs in a non-interactive
// context (typically the git smudge filter) and an age plugin asks for input.
// age.Decrypt surfaces this as an identity-level failure and falls through to
// the next identity in the list, which is how plugin identities stay
// inert during checkout. Surfaced to the user as a hint to re-run interactively.
var ErrNoTTY = errors.New("plugin requested interaction but no terminal is available; run `sesam reveal` and tap your key if necessary")

// PluginUI bridges sesam to the age plugin protocol's user-interaction
// callbacks (see filippo.io/age/plugin.ClientUI). It is constructed once at
// command start; ClientUI() returns a fresh *plugin.ClientUI that can be
// passed to plugin.NewIdentity / plugin.NewRecipient.
//
// Interactive mode prompts on stderr/stdin and reads secrets through a
// raw-mode terminal. Non-interactive mode refuses every prompt with
// ErrNoTTY so a smudge filter never blocks on a hardware token.
type PluginUI struct {
	interactive bool
	stdin       io.Reader
	stderr      io.Writer
}

// NewInteractivePluginUI builds a PluginUI that prompts on stderr/stdin.
// Use it for foreground CLI commands (init, seal, reveal, tell, …).
func NewInteractivePluginUI() *PluginUI {
	return &PluginUI{interactive: true, stdin: os.Stdin, stderr: os.Stderr}
}

// NewNonInteractivePluginUI builds a PluginUI that fails every prompt with
// ErrNoTTY. Use it for the long-running git filter, where stdin is owned by
// git's pkt-line protocol and any prompt would corrupt the stream.
func NewNonInteractivePluginUI() *PluginUI {
	return &PluginUI{interactive: false, stdin: os.Stdin, stderr: os.Stderr}
}

// ClientUI returns a *plugin.ClientUI bound to this PluginUI. Each call
// allocates a fresh struct; plugins never share callback state.
func (p *PluginUI) ClientUI() *plugin.ClientUI {
	return &plugin.ClientUI{
		DisplayMessage: p.displayMessage,
		RequestValue:   p.requestValue,
		Confirm:        p.confirm,
		WaitTimer:      p.waitTimer,
	}
}

func (p *PluginUI) displayMessage(name, message string) error {
	if !p.interactive {
		return ErrNoTTY
	}
	_, err := fmt.Fprintf(p.stderr, "[sesam-%s] %s\n", name, message)
	return err
}

func (p *PluginUI) requestValue(name, prompt string, secret bool) (string, error) {
	fmt.Println("request", name, prompt, secret)
	if !p.interactive {
		return "", ErrNoTTY
	}
	if _, err := fmt.Fprintf(p.stderr, "[sesam-%s] %s ", name, prompt); err != nil {
		return "", err
	}

	value, err := p.readValue(secret)
	if err != nil {
		return "", err
	}

	// After a secret is supplied the plugin typically blocks on a touch
	// interaction, with no further protocol messages until the user taps.
	// Hint at it now so the upcoming silence isn't mistaken for a hang.
	// Harmless when the plugin doesn't actually need a touch.
	if secret {
		_, _ = fmt.Fprintf(p.stderr, "[sesam-%s] touch your security key now if it starts to flash\n", name)
	}

	return value, nil
}

func (p *PluginUI) readValue(secret bool) (string, error) {
	fmt.Println("read", secret)
	if secret {
		//nolint:gosec // file descriptors are bounded by the OS
		if f, ok := p.stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			//nolint:gosec
			b, err := term.ReadPassword(int(f.Fd()))
			_, _ = fmt.Fprintln(p.stderr)
			if err != nil {
				return "", err
			}
			return string(b), nil
		}
	}

	line, err := bufio.NewReader(p.stdin).ReadString('\n')
	if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (p *PluginUI) confirm(name, prompt, yes, no string) (bool, error) {
	if !p.interactive {
		return false, ErrNoTTY
	}
	if no == "" {
		no = "no"
	}
	if _, err := fmt.Fprintf(p.stderr, "[sesam-%s] %s [%s/%s] ", name, prompt, yes, no); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(p.stdin).ReadString('\n')
	if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(line), yes), nil
}

// announcePluginCall is invoked by pluginIdentityWithHint just before the
// plugin subprocess is spawned. It prints a single line so the user knows a
// PIN/touch prompt is imminent - the plugin itself owns the PIN flow
// (sesam-yubikey reads /dev/tty directly, bypassing the protocol's
// request-secret), so this is sesam's only opportunity to set expectations
// before control transfers.
func (p *PluginUI) announcePluginCall(name string) {
	if !p.interactive {
		return
	}
	_, _ = fmt.Fprintf(p.stderr, "[sesam-%s] starting — enter PIN if prompted, then touch your security key when it flashes\n", name)
}

func (p *PluginUI) waitTimer(name string) {
	if !p.interactive {
		return
	}
	_, _ = fmt.Fprintf(p.stderr, "[sesam-%s] waiting — touch your security key now if it is flashing\n", name)
}
