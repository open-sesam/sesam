package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"
)

var SupportedForges = []string{
	"github",
	"gitlab",
	"codeberg",
}

// KeySource records where a public key originally came from. It is
// stored alongside the key itself in the audit log so that a later
// `verify --forge` can refetch and compare against the recorded value.
//
// Valid values are either KeySourceManual (the key was given verbatim
// in the config) or one of the spec forms understood by
// ResolveRecipient (e.g. "github:alice", "https://example.com/k.pub",
// "file://keys/k.pub").
type KeySource string

// KeySourceManual marks a key that was provided directly as raw key
// material in the config, rather than resolved from a forge id, URL,
// or file path. All other source values describe a specific way how
// the key was retrieved and (potentially) could be retrieved again.
const KeySourceManual KeySource = "manual"

// Recipient is the public part of an Identity.
// It is called "Recipient" because it references a person that
// is later to decrypt a secret.
type Recipient struct {
	age.Recipient
	comparablePublicKey
	Source KeySource `json:"-"`
}

func (r *Recipient) MarshalJSON() ([]byte, error) {
	return json.Marshal(UserPubKey{
		Key:    r.String(),
		Source: r.Source,
	})
}

// Recipients is a helper to manage several recipients
type Recipients []*Recipient

func (rs Recipients) AgeRecipients() []age.Recipient {
	ageRecps := make([]age.Recipient, 0, len(rs))
	for _, recp := range rs {
		ageRecps = append(ageRecps, recp.Recipient)
	}

	return ageRecps
}

func (rs Recipients) UserPubKeys() []UserPubKey {
	upks := make([]UserPubKey, 0, len(rs))
	for _, recp := range rs {
		upks = append(upks, UserPubKey{
			Key:    recp.String(),
			Source: recp.Source,
		})
	}

	return upks
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

// maxKeyMaterialSize bounds the bytes we accept from a single forge
// fetch or local key file. Forge endpoints can return several keys at
// once (one per line), which is why this is generous.
const maxKeyMaterialSize = 32 * 1024

// ResolveRecipient handles special recipient spec forms (forge ids
// like "github:user", "https://..." links, and "file://..." paths).
// All other inputs are returned verbatim and recorded as
// KeySourceManual.
//
// The returned source records the spec form so that the caller can
// store it in the audit log alongside the resolved key material.
//
// file:// paths are read through root and must be relative (i.e.
// sesam-relative), so the key file lives inside the repository and
// every other admin can resolve the same spec.
func ResolveRecipient(ctx context.Context, root *os.Root, pubKeySpec string) ([]string, KeySource, error) {
	var forgeURL string
	switch {
	case strings.HasPrefix(pubKeySpec, "github:"):
		forgeURL = fmt.Sprintf("https://github.com/%s.keys", url.QueryEscape(forgeIdToUser(pubKeySpec)))
	case strings.HasPrefix(pubKeySpec, "gitlab:"):
		forgeURL = fmt.Sprintf("https://gitlab.com/%s.keys", url.QueryEscape(forgeIdToUser(pubKeySpec)))
	case strings.HasPrefix(pubKeySpec, "codeberg:"):
		forgeURL = fmt.Sprintf("https://codeberg.org/%s.keys", url.QueryEscape(forgeIdToUser(pubKeySpec)))
	case strings.HasPrefix(pubKeySpec, "https://"):
		forgeURL = pubKeySpec
	case strings.HasPrefix(pubKeySpec, "file://"):
		// Relative so the file lives in the repo and other admins can
		// resolve the same spec; root confines the read to the repo.
		path := strings.TrimPrefix(pubKeySpec, "file://")
		if filepath.IsAbs(path) {
			return nil, "", fmt.Errorf("file:// recipient path must be relative to the repository: %s", pubKeySpec)
		}
		if root == nil {
			return nil, "", fmt.Errorf("cannot resolve %s without a repository root", pubKeySpec)
		}

		fd, err := root.Open(path)
		if err != nil {
			return nil, "", fmt.Errorf("failed to open %s: %w", pubKeySpec, err)
		}

		defer closeLogged(fd)

		data, err := io.ReadAll(io.LimitReader(fd, maxKeyMaterialSize))
		if err != nil {
			return nil, "", fmt.Errorf("failed to read %s: %w", pubKeySpec, err)
		}

		// Like the forge/https branch: one key per line, trailing
		// newlines trimmed (age rejects keys with a trailing '\n').
		return splitByLine(string(data)), KeySource(pubKeySpec), nil
	default:
		// pass through, assume it was directly specified in the config.
		return []string{pubKeySpec}, KeySourceManual, nil
	}

	keys, err := resolveLink(ctx, forgeURL)
	return keys, KeySource(pubKeySpec), err
}

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

// resolveLink downloads the public-key material at the given https URL.
func resolveLink(ctx context.Context, url string, client ...*http.Client) ([]string, error) {
	if !strings.HasPrefix(url, "https://") {
		// we should not download public keys over http:// or whatever.
		// https is not ideal either, so links should be noted in the docs to be difficult from a security perspective.
		return nil, fmt.Errorf("unsupported protocol scheme: %s", url)
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

	tr := io.LimitReader(resp.Body, maxKeyMaterialSize)
	buf := bytes.Buffer{}
	_, err = io.Copy(&buf, tr)
	return splitByLine(buf.String()), err
}

// ParseRecipient turns a public key string into a recipient age can use to
// encrypt. Accepts X25519 (`age1…`), hybrid (`age1pq1…`), age plugin recipients
// (`age1yubikey1…`, `age1tpm1…`, …) and SSH public keys. pluginUI is required
// when arg may be a plugin recipient; pass NewInteractivePluginUI() when in
// doubt - it is invoked only if a plugin actually prompts during Wrap.
// This function does not resolve forge-ids or links.
func ParseRecipient(arg string, pluginUI *PluginUI) (*Recipient, error) {
	var r age.Recipient
	var s string
	var err error

	// NOTE: Code based on age cli.
	switch {
	case strings.HasPrefix(arg, "age1pq1"):
		hr, err := age.ParseHybridRecipient(arg)
		if err != nil {
			return nil, err
		}

		r, s = hr, hr.String()
	case strings.HasPrefix(arg, "age1"):
		// X25519 (HRP "age") and plugin recipients (HRP "age1<name>") share
		// the `age1` literal prefix. Try X25519 first; on HRP mismatch fall
		// through to plugin parsing so e.g. `age1yubikey1…` resolves.
		xr, xerr := age.ParseX25519Recipient(arg)
		if xerr == nil {
			r, s = xr, xr.String()
			break
		}
		pr, perr := parsePluginRecipient(arg, pluginUI)
		if perr != nil {
			return nil, fmt.Errorf("not a recognised age recipient: %w", errors.Join(xerr, perr))
		}
		r, s = pr.Recipient, pr.String()
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
		Source:              KeySourceManual,
	}, err
}

func parsePluginRecipient(arg string, pluginUI *PluginUI) (*Recipient, error) {
	if pluginUI == nil {
		return nil, fmt.Errorf("plugin recipient requires a PluginUI; pass NewInteractivePluginUI()")
	}

	pr, err := plugin.NewRecipient(arg, pluginUI.ClientUI())
	if err != nil {
		return nil, err
	}
	return &Recipient{
		Recipient:           pr,
		comparablePublicKey: newStringPubKey(pr.String()),
	}, nil
}

// ParseRecipients parses one or more newline-separated recipient keys.
func ParseRecipients(recps []string, pluginUI *PluginUI) (Recipients, error) {
	var recipients Recipients

	for _, recp := range recps {
		recp, err := ParseRecipient(recp, pluginUI)
		if err != nil {
			return nil, err
		}

		recipients = append(recipients, recp)
	}

	return recipients, nil
}

func ParseAndResolveRecipients(ctx context.Context, root *os.Root, pubKeySpecs []string, pluginUI *PluginUI) (Recipients, error) {
	recps := make(Recipients, 0, len(pubKeySpecs))
	for idx, pubKeySpec := range pubKeySpecs {
		rawPubKeys, source, err := ResolveRecipient(ctx, root, pubKeySpec)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve recipient %s (#%d): %w", pubKeySpec, idx, err)
		}

		subRecps, err := ParseRecipients(rawPubKeys, pluginUI)
		if err != nil {
			return nil, fmt.Errorf("failed to parse recipient %s (#%d): %w", rawPubKeys, idx, err)
		}

		for i := range subRecps {
			subRecps[i].Source = source
		}

		recps = append(recps, subRecps...)
	}

	return recps, nil
}
