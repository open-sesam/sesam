package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"log/slog"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/chzyer/readline"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

// TODO: We might need to think about a way to destroy identities in memory after they are not longer needed.

// ParseIdentities parses raw key bytes into age identities. It tries native
// age keys first, then falls back to SSH key parsing. Passphrase protected keys are supported
// via the `passphraseProvider`.
func ParseIdentities(data []byte, passphraseProvider PassphraseProvider) ([]age.Identity, error) {
	// Try native age identities first (AGE-SECRET-KEY-1...).
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err == nil {
		return ids, nil
	}

	// Try parsing it as an unencrypted SSH key first.
	id, err := agessh.ParseIdentity(data)
	if err == nil {
		return []age.Identity{id}, nil
	}

	if _, ok := err.(*ssh.PassphraseMissingError); !ok {
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

	rawKey, err := ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SSH key: %w", err)
	}

	wrapErr := func(id age.Identity, err error) ([]age.Identity, error) {
		if err != nil {
			return nil, err
		}

		return []age.Identity{id}, nil
	}

	// NOTE: This is the same as agessh.ParseIdentities(), but without the parsing..
	// If age ever extends the list of supported ssh keys we have to intervene here.
	switch k := rawKey.(type) {
	case *ed25519.PrivateKey:
		return wrapErr(agessh.NewEd25519Identity(*k))
	// ParseRawPrivateKey returns inconsistent types. See Issue 429.
	case ed25519.PrivateKey:
		return wrapErr(agessh.NewEd25519Identity(k))
	case *rsa.PrivateKey:
		return wrapErr(agessh.NewRSAIdentity(k))
	default:
		return nil, fmt.Errorf("unsupported ssh key type: %T", k)
	}
}

type PassphraseProvider interface {
	ReadPassphrase() ([]byte, error)
}

type StdinPassphraseProvider struct{}

func (spp *StdinPassphraseProvider) ReadPassphrase() ([]byte, error) {
	return readline.Password("Passphrase: ")
}

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
