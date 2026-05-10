package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// Recipient is the public part of an Identity.
// It is called "Recipient" because it references a person that
// is later to decrypt a secret.
type Recipient struct {
	age.Recipient
	comparablePublicKey
}

// Recipients is a helper to manage several recipients
type Recipients []*Recipient

// CacheMode defines what to do with downloaded public keys.
type CacheMode int

const (
	CacheModeNone = CacheMode(1 << iota)
	CacheModeRead
	CacheModeWrite
	CacheModeReadWrite = CacheModeRead | CacheModeWrite
)

func (rs Recipients) AgeRecipients() []age.Recipient {
	ageRecps := make([]age.Recipient, 0, len(rs))
	for _, recp := range rs {
		ageRecps = append(ageRecps, recp.Recipient)
	}

	return ageRecps
}

func (rs Recipients) Strings() []string {
	strs := make([]string, 0, len(rs))
	for _, recp := range rs {
		strs = append(strs, recp.String())
	}

	return strs
}

func forgeIdToUser(arg string) string {
	_, user, _ := strings.Cut(arg, ":")
	return strings.TrimSpace(user)
}

// ResolveRecipient will handle special recipient types like forge-id
// (github:user, ...), links and paths. All other recipients are passed through.
//
// It will return the cleaned version that can be given to ParseRecipient().
// Links and forge-id will be cached in `sesamDir`.
func ResolveRecipient(ctx context.Context, sesamDir string, arg string, cacheMode CacheMode) ([]string, error) {
	switch {
	case strings.HasPrefix(arg, "github:"):
		url := fmt.Sprintf("https://github.com/%s.keys", url.QueryEscape(forgeIdToUser(arg)))
		return resolveCachedLink(ctx, sesamDir, url, cacheMode)
	// TODO: gitlab uses json; fix
	// case strings.HasPrefix(arg, "gitlab:"):
	// 	url := fmt.Sprintf("https://gitlab.com/%s.keys", url.QueryEscape(forgeIdToUser(arg)))
	// 	return resolveCachedLink(ctx, sesamDir, url, cacheMode)
	case strings.HasPrefix(arg, "codeberg:"):
		url := fmt.Sprintf("https://codeberg.org/%s.keys", url.QueryEscape(forgeIdToUser(arg)))
		return resolveCachedLink(ctx, sesamDir, url, cacheMode)
	case strings.HasPrefix(arg, "https://"):
		return resolveCachedLink(ctx, sesamDir, arg, cacheMode)
	case strings.HasPrefix(arg, "file://"):
		path := strings.TrimPrefix(arg, "file://")
		if err := validSecretPath(sesamDir, path); err != nil {
			return nil, fmt.Errorf("invalid file:// path (%s): %w", arg, err)
		}

		//nolint:gosec
		fd, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %w", arg, err)
		}

		defer closeLogged(fd)

		data, err := io.ReadAll(io.LimitReader(fd, 4096))
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", arg, err)
		}

		return []string{string(data)}, nil
	default:
		// pass through:
		return []string{arg}, nil
	}
}

func cachePath(sesamDir, url string) string {
	return filepath.Join(sesamDir, ".sesam", "links", strings.ReplaceAll(url, "/", "_"))
}

// TODO: implement command to check if links and forge-ids are out-dated? Maybe part of verify?

func splitByLine(s string) []string {
	lines := []string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		lines = append(lines, line)
	}

	return lines
}

// resolveCachedLink will download the specified `url` and write it to a cache under `sesamDir`.
// If the cached response is already available, then it is returned directly.
func resolveCachedLink(ctx context.Context, sesamDir, url string, cacheMode CacheMode, client ...*http.Client) ([]string, error) {
	if !strings.HasPrefix(url, "https://") {
		// we should not download public keys over http:// or whatever.
		// https is not ideal either, so links should be noted in the docs to be difficult from a security perspective.
		return nil, fmt.Errorf("unsupported protocol scheme: %s", url)
	}

	cachePath := cachePath(sesamDir, url)

	if cacheMode&CacheModeRead > 0 {
		//nolint:gosec
		data, err := os.ReadFile(cachePath)
		if err == nil {
			return splitByLine(string(data)), nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	var hc *http.Client
	if len(client) > 0 && client[0] != nil {
		hc = client[0]
	} else {
		hc = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer closeLogged(resp.Body)

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s failed with code %d", url, resp.StatusCode)
	}

	// Limit response size so cannot be DoS'd by large responses:
	const maxSize = 32 * 1024

	tr := io.LimitReader(resp.Body, maxSize)
	if cacheMode&CacheModeWrite > 0 {
		_ = os.MkdirAll(filepath.Dir(cachePath), 0o700)

		//nolint:gosec
		cacheFd, err := os.OpenFile(cachePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE|os.O_SYNC, 0o600)
		if err != nil {
			return nil, fmt.Errorf("failed to create cache path: %w", err)
		}

		defer closeLogged(cacheFd)
		tr = io.TeeReader(tr, cacheFd)
	}

	buf := bytes.Buffer{}
	_, err = io.Copy(&buf, tr)
	return splitByLine(buf.String()), err
}

// ParseRecipient will turn a public key to a recipient that age can understand.
// This function does not resolve forge-ids or links.
func ParseRecipient(arg string) (*Recipient, error) {
	var r age.Recipient
	var s string
	var err error

	// NOTE: Code based on age cli.
	// TODO: For yubikeys etc. we need to support a couple more lines here I guess.
	switch {
	case strings.HasPrefix(arg, "age1pq1"):
		hr, err := age.ParseHybridRecipient(arg)
		if err != nil {
			return nil, err
		}

		r, s = hr, hr.String()
	case strings.HasPrefix(arg, "age1"):
		xr, err := age.ParseX25519Recipient(arg)
		if err != nil {
			return nil, err
		}

		r, s = xr, xr.String()
	case strings.HasPrefix(arg, "ssh-"):
		// ssh keys have no stringer sadly. Incoming ssh keys might contain comments (like user@host) or options.
		// which can making comparison hard. Parse it therefore and re-marshal to strip that kind of stops.
		sshPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(arg))
		if err != nil {
			return nil, err
		}

		sr, err := agessh.ParseRecipient(arg)
		if err != nil {
			return nil, err
		}

		r, s = sr, string(ssh.MarshalAuthorizedKey(sshPub))
	default:
		return nil, fmt.Errorf("unknown recipient type: %s", arg)
	}

	spk := newStringPubKey(s)
	return &Recipient{
		Recipient:           r,
		comparablePublicKey: spk,
	}, err
}

// ParseRecipients parses one or more newline-separated recipient keys.
func ParseRecipients(recps []string) (Recipients, error) {
	var recipients Recipients

	for _, recp := range recps {
		recp, err := ParseRecipient(recp)
		if err != nil {
			return nil, err
		}

		recipients = append(recipients, recp)
	}

	return recipients, nil
}

func ParseAndResolveRecipients(ctx context.Context, sesamDir string, pubKeySpecs []string) (Recipients, error) {
	recps := make(Recipients, 0, len(pubKeySpecs))
	for idx, pubKeySpec := range pubKeySpecs {
		rawPubKeys, err := ResolveRecipient(
			ctx,
			sesamDir,
			pubKeySpec,
			CacheModeReadWrite,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve recipient %s (#%d): %w", pubKeySpec, idx, err)
		}

		subRecps, err := ParseRecipients(rawPubKeys)
		if err != nil {
			return nil, fmt.Errorf("failed to parse recipient %s (#%d): %w", rawPubKeys, idx, err)
		}

		recps = append(recps, subRecps...)
	}

	return recps, nil
}
