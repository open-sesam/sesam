package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"github.com/chzyer/readline"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

// TODO: We might need to think about a way to destroy identities in memory after they are not longer needed.

// comparablePublicKey is a public key that can be compared with another key safely.
type comparablePublicKey interface {
	Equal(o comparablePublicKey) bool
	String() string
}

// age public keys are only available as string in the api.
// Good enough for comparing them, albeit a bit awkward.
// We can do something similar for ssh keys, just need to make
// sure they are normalized (no comments like user@host)
type stringPubKey string

// Identity references a private key of a user.
type Identity struct {
	age.Identity
	pub comparablePublicKey
}

// Identities is a list of Identity.
// It just exists to allow some common helper types.
type Identities []*Identity

// PassphraseProvider describes anything that can give you a password.
type PassphraseProvider interface {
	ReadPassphrase() ([]byte, error)
}

// StdinPassphraseProvider is a simple PassphraseProvider that reads a password from stdin.
type StdinPassphraseProvider struct{}

// KeyringPassphraseProvider tries to read the passphrase from the system
// keyring (GNOME Keyring, KWallet, macOS Keychain, Windows Credential Manager).
// If no entry exists, it falls back to prompting via the given fallback provider
// and caches the passphrase in the keyring on success.
type KeyringPassphraseProvider struct {
	// KeyFingerprint identifies which key this passphrase is for.
	// Used as the keyring item name to support multiple SSH keys.
	KeyFingerprint string

	// Fallback is used to prompt the user when the keyring has no entry.
	Fallback PassphraseProvider
}

const keyringService = "sesam"

func newStringPubKey(s string) stringPubKey {
	// just make sure we don't have formatting accidents...
	return stringPubKey(strings.TrimSpace(s))
}

func (spk stringPubKey) Equal(o comparablePublicKey) bool {
	ospk, ok := o.(stringPubKey)
	if !ok {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(spk), []byte(ospk)) == 1
}

func (spk stringPubKey) String() string {
	return string(spk)
}

func (gi *Identity) Public() comparablePublicKey {
	return gi.pub
}

func (ids Identities) AgeIdentities() []age.Identity {
	ageIds := make([]age.Identity, 0, len(ids))
	for _, id := range ids {
		ageIds = append(ageIds, id.Identity)
	}

	return ageIds
}

func (ids Identities) RecipientStrings() []string {
	strs := make([]string, 0, len(ids))
	for _, id := range ids {
		strs = append(strs, id.pub.String())
	}

	return strs
}

func sshKeyToIdentity(rawKey any) (*Identity, error) {
	// NOTE: This is the same as agessh.ParseIdentities(), but without the parsing..
	// If age ever extends the list of supported ssh keys we have to intervene here.
	switch k := rawKey.(type) {
	case *ed25519.PrivateKey:
		id, err := agessh.NewEd25519Identity(*k)
		if err != nil {
			return nil, err
		}

		pub := k.Public().(ed25519.PublicKey)
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return nil, err
		}

		return &Identity{
			Identity: id,
			pub:      newStringPubKey(string(ssh.MarshalAuthorizedKey(sshPub))),
		}, nil
	case ed25519.PrivateKey:
		id, err := agessh.NewEd25519Identity(k)
		if err != nil {
			return nil, err
		}

		pub := k.Public().(ed25519.PublicKey)
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return nil, err
		}

		return &Identity{
			Identity: id,
			pub:      newStringPubKey(string(ssh.MarshalAuthorizedKey(sshPub))),
		}, nil
	case *rsa.PrivateKey:
		id, err := agessh.NewRSAIdentity(k)
		if err != nil {
			return nil, err
		}

		pub := k.Public().(*rsa.PublicKey)
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return nil, err
		}

		return &Identity{
			Identity: id,
			pub:      newStringPubKey(string(ssh.MarshalAuthorizedKey(sshPub))),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported ssh key type: %T", k)
	}
}

// ParseIdentity parses raw key bytes into an age identity. It accepts native
// age identities, age plugin identities (`AGE-PLUGIN-…`), and SSH private
// keys (with passphrase support via passphraseProvider). pluginUI is required
// for plugin identities and may be nil otherwise.
//
// age and plugin identity files commonly carry `# created:` and
// `# public key: …` header comments (the output format of age-keygen and
// age-plugin-yubikey). Those are tolerated; the first non-comment line is
// taken as the identity payload. For plugin identities the `# public key: …`
// line is the recipient encoding sesam compares against the audit log and is
// therefore required.
func ParseIdentity(key string, passphraseProvider PassphraseProvider, pluginUI *PluginUI) (*Identity, error) {
	ageLine, recipientHint := scanAgeIdentity(key)

	switch {
	case strings.HasPrefix(ageLine, "AGE-SECRET-KEY-1"):
		x25519id, err := age.ParseX25519Identity(ageLine)
		if err != nil {
			return nil, err
		}

		return &Identity{
			Identity: x25519id,
			pub:      newStringPubKey(x25519id.Recipient().String()),
		}, nil
	case strings.HasPrefix(ageLine, "AGE-SECRET-KEY-PQ-1"):
		hybridID, err := age.ParseHybridIdentity(ageLine)
		if err != nil {
			return nil, err
		}

		return &Identity{
			Identity: hybridID,
			pub:      newStringPubKey(hybridID.Recipient().String()),
		}, nil
	case strings.HasPrefix(ageLine, "AGE-PLUGIN-"):
		return parsePluginIdentity(ageLine, recipientHint, pluginUI)
	}

	// Try parsing it as an unencrypted SSH key first, since it's apparently not age.
	rawKey, err := ssh.ParseRawPrivateKey([]byte(key))
	if err == nil {
		// no passphrase was required.
		return sshKeyToIdentity(rawKey)
	}

	targetErr := &ssh.PassphraseMissingError{}
	if !errors.As(err, &targetErr) {
		// not a passphrase issue, so report early.
		return nil, fmt.Errorf("key is not parse-able: %w", err)
	}

	if passphraseProvider == nil {
		return nil, fmt.Errorf("no passphrase supplied")
	}

	passphrase, err := passphraseProvider.ReadPassphrase()
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}

	rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(key), passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SSH key: %w", err)
	}

	return sshKeyToIdentity(rawKey)
}

// scanAgeIdentity walks an identity file, returning the first non-comment
// line (the identity payload) and any `# public key: …` value carried in
// the file's header comments. age-keygen emits `# public key:`,
// age-plugin-yubikey emits `# Recipient:`; matching is case-insensitive on
// both the key and the prefix so either format is accepted. Empty strings
// if no match.
func scanAgeIdentity(data string) (identityLine, publicKey string) {
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			if identityLine == "" {
				identityLine = line
			}
			continue
		}

		// Comment line: try to extract a public-key / recipient header.
		// Format: "# <key>: <value>" with key match case-insensitive.
		body := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		key, value, ok := strings.Cut(body, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "public key":
			publicKey = strings.TrimSpace(value)
		case "recipient":
			if publicKey == "" {
				publicKey = strings.TrimSpace(value)
			}
		}
	}

	return
}

// parsePluginIdentity wraps a plugin.Identity into core's Identity type.
// recipientHint is the `# public key: …` value from the identity file - it
// is required because plugin.Identity.Recipient().String() returns a
// placeholder ("<identity-based recipient>") rather than the recipient
// encoding sesam needs to match identities to users.
func parsePluginIdentity(ageLine, recipientHint string, pluginUI *PluginUI) (*Identity, error) {
	pluginIdentity, err := plugin.NewIdentity(ageLine, pluginUI.ClientUI())
	if err != nil {
		return nil, fmt.Errorf("parse plugin identity: %w", err)
	}

	if recipientHint == "" {
		return nil, fmt.Errorf(
			"plugin identity for %q is missing a `# public key: …` header; sesam needs the recipient to map identities to users",
			pluginIdentity.Name(),
		)
	}

	// Wrap so we can print a heads-up before handing control to the plugin
	// subprocess. age-plugin-yubikey (and other hardware plugins) bypass the
	// plugin protocol's request-secret and read the PIN directly from
	// /dev/tty, so PluginUI.requestValue never fires - this Unwrap hook is
	// the only place sesam can prompt the user before the plugin takes over.
	return &Identity{
		Identity: &pluginIdentityWithHint{inner: pluginIdentity, ui: pluginUI},
		pub:      newStringPubKey(recipientHint),
	}, nil
}

// pluginIdentityWithHint prints a user-facing notice before the plugin
// subprocess starts, so the PIN prompt and the touch wait aren't
// uninterpreted silence to the user. The hint fires only on the first
// Unwrap: age.Decrypt tries each identity against every recipient stanza
// in the file, so without the guard we'd announce N times in a row for an
// audit key encrypted to N users.
type pluginIdentityWithHint struct {
	inner    *plugin.Identity
	ui       *PluginUI
	announce sync.Once
}

func (p *pluginIdentityWithHint) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	p.announce.Do(func() { p.ui.announcePluginCall(p.inner.Name()) })
	return p.inner.Unwrap(stanzas)
}

func (spp *StdinPassphraseProvider) ReadPassphrase() ([]byte, error) {
	return readline.Password("Passphrase: ")
}

func (kpp *KeyringPassphraseProvider) ReadPassphrase() ([]byte, error) {
	stored, err := keyring.Get(keyringService, kpp.KeyFingerprint)
	if err == nil {
		return []byte(stored), nil
	}

	if kpp.Fallback == nil {
		return nil, fmt.Errorf("no passphrase in keyring and no fallback provider")
	}

	passphrase, err := kpp.Fallback.ReadPassphrase()
	if err != nil {
		return nil, err
	}

	// Cache for next time. Non-fatal if this fails (e.g. no keyring daemon).
	err = keyring.Set(keyringService, kpp.KeyFingerprint, string(passphrase))
	if err != nil {
		slog.Warn("failed to set key in keyring", slog.Any("err", err))
	}

	return passphrase, nil
}

// IdentityToUser checks which public key corresponds to which recipient public key.
// This function returns the mapped user or an error.
//
// It will fail when:
// - There is no public key for this user.
// - There are several matching users (techically possible, but disencouraged).
// - We failed to test the relation by a quick test of encrypt/decrypt.
func IdentityToUser(id *Identity, userToPub map[string]Recipients) (string, error) {
	ownPub := id.Public()

	var matchCount int
	var matchedUser string
	var matchedRecipient *Recipient

	for userName, recps := range userToPub {
		for _, recp := range recps {
			if ownPub.Equal(recp.comparablePublicKey) {
				matchCount++
				matchedUser = userName
				matchedRecipient = recp
			}
		}
	}

	if matchCount == 0 {
		return "", errors.New("no matching users found")
	}

	if matchCount > 1 {
		return "", errors.New("too many matching users found")
	}

	// encrypt a dummy text with the matched recipient:
	const dummyText = "sesam open"
	buf := &bytes.Buffer{}
	w, _ := age.Encrypt(buf, matchedRecipient)
	_, _ = w.Write([]byte(dummyText))
	_ = w.Close()

	// decrypt it with the supplied identity to check if both are really linked:
	r, err := age.Decrypt(buf, id)
	if err != nil {
		return "", fmt.Errorf("mismatch between recipient and id: %w", err)
	}
	resp, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("mismatch between recipient and id: %w", err)
	}

	if sr := string(resp); sr != dummyText {
		return "", fmt.Errorf("encrypt+decrypt test worked but different outcome: %s", sr)
	}

	// all good, we can return.
	return matchedUser, nil
}
