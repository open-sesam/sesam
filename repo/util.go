package repo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/open-sesam/sesam/core"
)

// expandHomeDir expands "~" and "~/..." in path input.
func expandHomeDir(path string) (string, error) {
	switch {
	case path == "~":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		return homeDir, nil
	case strings.HasPrefix(path, "~/"):
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		return filepath.Join(homeDir, strings.TrimPrefix(path, "~/")), nil
	default:
		return path, nil
	}
}

func identityToUser(identities core.Identities, users map[string]core.Recipients) (string, *core.Identity, error) {
	var lastErr error

	for _, identity := range identities {
		var user string
		user, lastErr = core.IdentityToUser(identity, users)
		if lastErr == nil {
			return user, identity, nil
		}
	}

	return "", nil, fmt.Errorf("no loaded identity matches any known user (%w)", lastErr)
}

// loadIdentities reads all given paths and parses all identities. Encrypted
// identities are unlocked via the system keyring, falling back to askpass and
// then stdin when allowed.
func loadIdentities(identityPaths []string, pluginUI *core.PluginUI) (core.Identities, error) {
	return loadIdentitiesWith(identityPaths, RepoOpts{Interactive: true}.passphraseProvider, pluginUI)
}

// loadIdentitiesKeyringOnly is like loadIdentities but never prompts on stdin.
// It is required for the long-running smudge filter, where stdin is owned by
// the git pkt-line protocol and a passphrase prompt would corrupt the stream.
// If the keyring has no entry for an encrypted identity, parsing fails.
func loadIdentitiesKeyringOnly(identityPaths []string, pluginUI *core.PluginUI) (core.Identities, error) {
	return loadIdentitiesWith(identityPaths, RepoOpts{}.passphraseProvider, pluginUI)
}

func askpassRequired() string {
	for _, name := range []string{"SESAM_ASKPASS_REQUIRED", "GIT_ASKPASS_REQUIRED", "SSH_ASKPASS_REQUIRED"} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
		case "never":
			return "never"
		case "force":
			return "force"
		case "prefer":
			return "prefer"
		}
	}
	return "prefer"
}

// loadIdentitiesWith parses every identity at the given paths. newProvider
// builds the PassphraseProvider for a single identity, keyed by that key's own
// fingerprint, so each encrypted key gets a distinct keyring entry instead of
// sharing one (which would cross-contaminate passphrases between keys).
func loadIdentitiesWith(identityPaths []string, newProvider func(keyFingerprint string) core.PassphraseProvider, pluginUI *core.PluginUI) (core.Identities, error) {
	if len(identityPaths) == 0 {
		return nil, fmt.Errorf("at least one --identity or SESAM_ID env var required")
	}

	seen := make(map[string]bool)

	identities := make(core.Identities, 0, len(identityPaths))
	for _, identityPath := range identityPaths {
		if strings.TrimSpace(identityPath) == "" {
			return nil, fmt.Errorf("missing identity path: pass --identity")
		}

		expandedPath, err := expandHomeDir(identityPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve identity path: %w", err)
		}

		const maxIdentityFileBytes = 1024 * 1024
		data, err := core.ReadFileLimited(expandedPath, maxIdentityFileBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read identity %s: %w", expandedPath, err)
		}

		key := string(data)
		prompt := fmt.Sprintf("🔐 Passphrase for %s: ", filepath.Base(expandedPath))
		provider := newProvider(core.KeyFingerprint(data))
		identity, err := core.ParseIdentity(key, provider, pluginUI, prompt)
		if err != nil {
			return nil, err
		}

		idPub := identity.Public().String()
		if seen[idPub] {
			// just ignore duplicate identities.
			continue
		}

		identities = append(identities, identity)
		seen[idPub] = true
	}
	return identities, nil
}

// openGitRepo opens the git repository that contains sesamRoot. DetectDotGit
// walks up parent directories, so this works whether .sesam lives at the
// worktree root or in a subdir.
func openGitRepo(sesamDir string) (*git.Repository, error) {
	repo, err := git.PlainOpenWithOptions(sesamDir, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, fmt.Errorf("open git repo at %s: %w", sesamDir, err)
	}
	return repo, nil
}
