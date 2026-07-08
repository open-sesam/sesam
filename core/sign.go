package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/google/renameio/v2"
)

type SignDomain []byte

// Signer is similar to Identity (private part) but is used for signing only.
type Signer interface {
	Sign(domain SignDomain, data []byte) (string, error)
	PublicKey() []byte
	UserName() string
}

var (
	// See: https://en.wikipedia.org/wiki/Domain_separation
	SesamDomainSignSecretTag = SignDomain("sesam.secret.v1:")
	SesamDomainSignAuditTag  = SignDomain("sesam.audit.v1:")
)

type ed25519Signer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	user string
}

func (es *ed25519Signer) Sign(domain SignDomain, data []byte) (string, error) {
	sig, err := es.priv.Sign(rand.Reader, append(domain, data...), &ed25519.Options{})
	if err != nil {
		return "", err
	}

	return MulticodeEncode(sig, MhEdDSA), nil
}

func (es *ed25519Signer) PublicKey() []byte {
	return es.pub
}

func (es *ed25519Signer) UserName() string {
	return es.user
}

// LoadSignKey will load a signer specific to a user and decrypt it via `userIdentity`
func LoadSignKey(root *os.Root, user string, userIdentity age.Identity) (Signer, error) {
	if err := ValidUserName(user); err != nil {
		return nil, fmt.Errorf("invalid user name: %w", err)
	}

	signKeyPath := signKeyPath(user)

	cryptedSignPrivKeyFd, err := root.Open(signKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load sign key %s: %w", signKeyPath, err)
	}

	dr, err := age.Decrypt(io.LimitReader(cryptedSignPrivKeyFd, 16*1024), userIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt header of signing key: %w", err)
	}

	defer closeLogged(cryptedSignPrivKeyFd)

	signingKeyEncoded, err := io.ReadAll(dr)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt signing key: %w", err)
	}

	signPrivKeyRaw, code, err := multicodeDecode(string(bytes.TrimSpace(signingKeyEncoded)))
	if err != nil {
		return nil, fmt.Errorf("failed to decode sign key %s: %w", signKeyPath, err)
	}
	if code != MhEd25519Priv {
		return nil, fmt.Errorf("unexpected multihash code %d for signing key, expected ed25519-priv", code)
	}

	// ed25519 priv keys should always be 64 bytes.
	if l := len(signPrivKeyRaw); l != 64 {
		return nil, fmt.Errorf("signing key has an unexpected length (%d) and not 64", l)
	}

	signPrivKey := ed25519.PrivateKey(signPrivKeyRaw)
	return &ed25519Signer{
		pub:  signPrivKey.Public().(ed25519.PublicKey),
		priv: signPrivKey,
		user: user,
	}, nil
}

// signKeyPath returns the repo-relative path of a user's signing key.
func signKeyPath(user string) string {
	return filepath.Join(".sesam", "signkeys", user+".age")
}

// GenerateSignKey will generate a new ed25519 signing key only accessible to `userRecipient`
func GenerateSignKey(root *os.Root, user string, userRecipient []age.Recipient) (Signer, error) {
	if err := ValidUserName(user); err != nil {
		return nil, fmt.Errorf("invalid user name: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key %s: %w", user, err)
	}

	if err := WriteSignKey(root, user, userRecipient, priv); err != nil {
		return nil, fmt.Errorf("failed to write signkey for %s: %w", user, err)
	}

	return &ed25519Signer{
		pub:  pub,
		priv: priv,
		user: user,
	}, nil
}

func WriteSignKey(root *os.Root, user string, userRecipient []age.Recipient, priv ed25519.PrivateKey) error {
	signKeyPath := signKeyPath(user)
	if err := root.MkdirAll(filepath.Dir(signKeyPath), 0o700); err != nil {
		return fmt.Errorf("failed to mkdir signing key dir: %w", err)
	}

	ageBuf := &bytes.Buffer{}
	wc, err := age.Encrypt(ageBuf, userRecipient...)
	if err != nil {
		return fmt.Errorf("failed to encrypt signing key: %w", err)
	}

	privMh := MulticodeEncode(priv[:], MhEd25519Priv)
	if _, err := wc.Write([]byte(privMh)); err != nil {
		return fmt.Errorf("failed to encrypt signing key: %w", err)
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("failed to close encrypted writer: %w", err)
	}

	if err := renameio.WriteFile(signKeyPath, ageBuf.Bytes(), 0o600, renameio.WithRoot(root), renameio.WithTempDir(SesamTmpDir())); err != nil {
		return fmt.Errorf("failed to write signing key %s: %w", signKeyPath, err)
	}

	return nil
}

// readAllSignatures finds all .sesam files under .sesam/objects/ and parses their signature footers.
func readAllSignatures(root *os.Root) ([]*secretFooter, error) {
	return readAllSignaturesForDir(root, filepath.Join(".sesam", "objects"))
}

func readAllSignaturesForDir(root *os.Root, objectsDir string) ([]*secretFooter, error) {
	var sigs []*secretFooter
	if _, err := root.Stat(objectsDir); os.IsNotExist(err) {
		// might happen if we're in the init phase
		return sigs, nil
	}

	err := fs.WalkDir(root.FS(), filepath.ToSlash(objectsDir), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".sesam") {
			return nil
		}

		fd, err := root.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open signature json %s: %w", path, err)
		}
		defer closeLogged(fd)

		_, sigDesc, err := readFooter(fd)
		if err != nil {
			return err
		}

		sigs = append(sigs, sigDesc)
		return nil
	})

	return sigs, err
}
