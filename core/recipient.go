package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// KeySource records where a public key originally came from. It is
// stored alongside the key itself in the audit log so that a later
// `verify --forge` can refetch and compare against the recorded value.
//
// Valid values are either KeySourceManual (the key was given verbatim
// in the config) or one of the spec forms understood by
// ResolveRecipient (e.g. "github:alice", "https://example.com/k.pub",
// "file:///path/to/k.pub").
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
	Source KeySource
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

func forgeIdToUser(arg string) string {
	_, user, _ := strings.Cut(arg, ":")
	return strings.TrimSpace(user)
}

// ResolveRecipient handles special recipient spec forms (forge ids
// like "github:user", "https://..." links, and "file://..." paths).
// All other inputs are returned verbatim and recorded as
// KeySourceManual.
//
// The returned source records the spec form so that the caller can
// store it in the audit log alongside the resolved key material.
func ResolveRecipient(ctx context.Context, pubKeySpec string) ([]string, KeySource, error) {
	switch {
	case strings.HasPrefix(pubKeySpec, "github:"):
		url := fmt.Sprintf("https://github.com/%s.keys", url.QueryEscape(forgeIdToUser(pubKeySpec)))
		v, err := resolveLink(ctx, url)
		return v, KeySource(pubKeySpec), err
	// TODO: gitlab uses json; fix
	// case strings.HasPrefix(pubKeySpec, "gitlab:"):
	// 	url := fmt.Sprintf("https://gitlab.com/%s.keys", url.QueryEscape(forgeIdToUser(pubKeySpec)))
	// 	v, err := resolveLink(ctx, url)
	// 	return v, KeySource(pubKeySpec), err
	case strings.HasPrefix(pubKeySpec, "codeberg:"):
		url := fmt.Sprintf("https://codeberg.org/%s.keys", url.QueryEscape(forgeIdToUser(pubKeySpec)))
		v, err := resolveLink(ctx, url)
		return v, KeySource(pubKeySpec), err
	case strings.HasPrefix(pubKeySpec, "https://"):
		v, err := resolveLink(ctx, pubKeySpec)
		return v, KeySource(pubKeySpec), err
	case strings.HasPrefix(pubKeySpec, "file://"):
		path := strings.TrimPrefix(pubKeySpec, "file://")

		//nolint:gosec
		fd, err := os.Open(path)
		if err != nil {
			return nil, "", fmt.Errorf("failed to open %s: %w", pubKeySpec, err)
		}

		defer closeLogged(fd)

		data, err := io.ReadAll(io.LimitReader(fd, 4096))
		if err != nil {
			return nil, "", fmt.Errorf("failed to read %s: %w", pubKeySpec, err)
		}

		return []string{string(data)}, KeySource(pubKeySpec), nil
	default:
		// pass through, assume it was directly specified in the config.
		return []string{pubKeySpec}, KeySourceManual, nil
	}
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

	// Limit response size so cannot be DoS'd by large responses:
	const maxSize = 32 * 1024

	tr := io.LimitReader(resp.Body, maxSize)

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
		Source:              KeySourceManual, // overwritten later, if applicable
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

func ParseAndResolveRecipients(ctx context.Context, pubKeySpecs []string) (Recipients, error) {
	recps := make(Recipients, 0, len(pubKeySpecs))
	for idx, pubKeySpec := range pubKeySpecs {
		rawPubKeys, source, err := ResolveRecipient(ctx, pubKeySpec)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve recipient %s (#%d): %w", pubKeySpec, idx, err)
		}

		subRecps, err := ParseRecipients(rawPubKeys)
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
