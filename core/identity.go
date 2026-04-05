package core

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/chzyer/readline"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

// TODO: We might need to think about a way to destroy identities in memory after they are not longer needed.

// ComparablePublicKey is a public key that can be compared with another key safely.
type ComparablePublicKey interface {
	Equal(o ComparablePublicKey) bool
}

// age public keys are only available as string in the api.
// Good enough for comparing them, albeit a bit awkward.
type stringPubKey string

func (spk stringPubKey) Equal(o ComparablePublicKey) bool {
	ospk, ok := o.(stringPubKey)
	if !ok {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(spk), []byte(ospk)) == 1
}

type cryptoPubKey struct {
	equalPubKey interface {
		// normal crypto.PublicKey type has no Equal method,
		// but all types implement it nevertheless.
		Equal(x crypto.PublicKey) bool
	}
}

func (cpk cryptoPubKey) Equal(o ComparablePublicKey) bool {
	ocpk, ok := o.(cryptoPubKey)
	if !ok {
		return false
	}

	return cpk.equalPubKey.Equal(ocpk.equalPubKey)
}

type Identity struct {
	age.Identity
	pub ComparablePublicKey
}

func (gi *Identity) Public() ComparablePublicKey {
	return gi.pub
}

type Identities []*Identity

func (ids Identities) AgeIdentities() []age.Identity {
	ageIds := make([]age.Identity, 0, len(ids))
	for _, id := range ids {
		ageIds = append(ageIds, id.Identity)
	}

	return ageIds
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

		return &Identity{
			Identity: id,
			pub:      cryptoPubKey{k.Public().(ed25519.PublicKey)},
		}, nil
	case ed25519.PrivateKey:
		id, err := agessh.NewEd25519Identity(k)
		if err != nil {
			return nil, err
		}

		return &Identity{
			Identity: id,
			pub:      cryptoPubKey{k.Public().(ed25519.PublicKey)},
		}, nil
	case *rsa.PrivateKey:
		id, err := agessh.NewRSAIdentity(k)
		if err != nil {
			return nil, err
		}

		return &Identity{
			Identity: id,
			pub:      cryptoPubKey{k.Public().(*rsa.PublicKey)},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported ssh key type: %T", k)
	}
}

// ParseIdentities parses raw key bytes into age identities. It tries native
// age keys first, then falls back to SSH key parsing. Passphrase protected keys are supported
// via the `passphraseProvider`.
func ParseIdentity(key string, passphraseProvider PassphraseProvider) (*Identity, error) {
	// Try native age identities first (AGE-SECRET-KEY-1...).
	switch {
	case strings.HasPrefix(key, "AGE-SECRET-KEY-1"):
		x25519id, err := age.ParseX25519Identity(key)
		if err != nil {
			return nil, err
		}

		return &Identity{
			Identity: x25519id,
			pub:      stringPubKey(x25519id.Recipient().String()),
		}, nil
	case strings.HasPrefix(key, "AGE-SECRET-KEY-PQ-1"):
		hybridID, err := age.ParseHybridIdentity(key)
		if err != nil {
			return nil, err
		}

		return &Identity{
			Identity: hybridID,
			pub:      stringPubKey(hybridID.Recipient().String()),
		}, nil
	}

	// Try parsing it as an unencrypted SSH key first, since it's apparently not age.
	rawKey, err := ssh.ParseRawPrivateKey([]byte(key))
	if err == nil {
		// no passphrase was required.
		return sshKeyToIdentity(rawKey)
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

	rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(key), passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SSH key: %w", err)
	}

	return sshKeyToIdentity(rawKey)
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
