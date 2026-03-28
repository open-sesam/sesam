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

	"filippo.io/age"
	"filippo.io/age/agessh"
)

type CacheMode int

const (
	CacheModeNone = CacheMode(1 << iota)
	CacheModeRead
	CacheModeWrite
	CacheModeReadWrite = CacheModeRead | CacheModeWrite
)

func forgeIdToUser(arg string) string {
	_, user, _ := strings.Cut(arg, ":")
	return strings.TrimSpace(user)
}

// ResolveRecipient will handle special recipient types like forge-id
// (github:user, ...), links and paths. All other recipients are passed through.
//
// It will return the cleaned version that can be given to ParseRecipient().
// Links and forge-id will be cached in `repoDir`.
func ResolveRecipient(ctx context.Context, repoDir string, arg string, cacheMode CacheMode) (string, error) {
	switch {
	case strings.HasPrefix(arg, "github:"):
		url := fmt.Sprintf("https://github.com/%s.keys", url.QueryEscape(forgeIdToUser(arg)))
		return resolveCachedLink(ctx, repoDir, url, cacheMode)
	case strings.HasPrefix(arg, "gitlab:"):
		url := fmt.Sprintf("https://gitlab.com/%s.keys", url.QueryEscape(forgeIdToUser(arg)))
		return resolveCachedLink(ctx, repoDir, url, cacheMode)
	case strings.HasPrefix(arg, "bitbucket:"):
		url := fmt.Sprintf("https://bitbucket.org/api/1.0/users/%s/ssh-keys", url.QueryEscape(forgeIdToUser(arg)))
		return resolveCachedLink(ctx, repoDir, url, cacheMode)
	case strings.HasPrefix(arg, "https://"):
		return resolveCachedLink(ctx, repoDir, arg, cacheMode)
	case strings.HasPrefix(arg, "file://"):
		// TODO: Strip "file://" prefix before reading. Also consider restricting
		// to paths within the repo directory to prevent reading arbitrary files.
		data, err := os.ReadFile(arg)
		if err != nil {
			return "", fmt.Errorf("failed to find %s: %w", arg, err)
		}

		return string(data), nil
	default:
		// pass through:
		return arg, nil
	}
}

func cachePath(repoDir, url string) string {
	return filepath.Join(repoDir, ".sesam", "links", strings.ReplaceAll(url, "/", "_"))
}

// TODO: implement command to check if links and forge-ids are out-dated? Maybe part of verify?

// TODO: Verify needs to inlcude the contents of the users/groups and public keys in the signature.
//       THIS MEANS WE HAVE TO INCLUDE THE ACTUAL PUBLIC KEY NOT JUST "github:sahib"

// resolveCachedLink will download the specified `url` and write it to a cache under `repoDir`.
// If the cached response is already available, then it is returned directly.
func resolveCachedLink(ctx context.Context, repoDir, url string, cacheMode CacheMode) (string, error) {
	if !strings.HasPrefix(url, "https://") {
		// we should not download public keys over http:// or whatever.
		// https is not ideal either, so links should be noted in the docs to be difficult from a security perspective.
		return "", fmt.Errorf("unsupported protocol scheme: %s", url)
	}

	cachePath := cachePath(repoDir, url)

	if cacheMode&CacheModeRead > 0 {
		data, err := os.ReadFile(cachePath)
		if err == nil {
			return string(data), nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("%s failed with code %d", url, resp.StatusCode)
	}

	// Limit response size so cannot be DoS'd by large responses:
	const maxSize = 32 * 1024

	tr := io.LimitReader(resp.Body, maxSize)
	if cacheMode&CacheModeWrite > 0 {
		_ = os.MkdirAll(filepath.Dir(cachePath), 0700)

		// Avoid being DDoS'd by big responses.
		cacheFd, err := os.Create(cachePath)
		if err != nil {
			return "", fmt.Errorf("failed to create cache path: %w", err)
		}

		defer cacheFd.Close()
		tr = io.TeeReader(tr, cacheFd)
	}

	buf := bytes.Buffer{}
	_, err = io.Copy(&buf, tr)
	return buf.String(), err
}

// ParseRecipient will turn a public key to a recipient that age can understand.
// This function does not resolve forge-ids or links.
func ParseRecipient(arg string) (age.Recipient, error) {
	var r age.Recipient
	var err error

	// NOTE: Shamelessly stolen from age cli.
	// TODO: For yubikeys etc. we need to support a couple more lines here I guess.
	switch {
	case strings.HasPrefix(arg, "age1pq1"):
		r, err = age.ParseHybridRecipient(arg)
	case strings.HasPrefix(arg, "age1"):
		r, err = age.ParseX25519Recipient(arg)
	case strings.HasPrefix(arg, "ssh-"):
		r, err = agessh.ParseRecipient(arg)
	default:
		return nil, fmt.Errorf("unknown recipient type: %s", arg)
	}

	return r, err
}
