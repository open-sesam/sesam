package repo

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/go-git/go-git/v5"
	"opensesam.org/sesam/core"
)

// ExpandHomeDir expands "~" and "~/..." in path input.
func ExpandHomeDir(path string) (string, error) {
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

		expandedPath, err := ExpandHomeDir(identityPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve identity path: %w", err)
		}

		const maxIdentityFileBytes = 1024 * 1024
		data, err := core.ReadFileLimited(expandedPath, maxIdentityFileBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read identity %s: %w", expandedPath, err)
		}

		key := string(data)
		keyFingerprint := core.KeyFingerprint(data)
		prompt := fmt.Sprintf("🔐 sesam passphrase for %s (%s): ", filepath.Base(expandedPath), keyFingerprint)
		provider := newProvider(keyFingerprint)
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

// ReadGitVersion runs `git --version` and parses the result into a semver.
func ReadGitVersion(ctx context.Context) (*semver.Version, error) {
	out, err := exec.CommandContext(ctx, "git", "--version").Output()
	if err != nil {
		return nil, fmt.Errorf("run git --version: %w", err)
	}
	return parseGitVersion(string(out))
}

// parseGitVersion extracts the version from `git --version` output. The format
// is "git version X.Y.Z", with vendor noise on some platforms - a "(Apple
// Git-154)" suffix on macOS, a ".windows.1" suffix on Windows - so we take the
// third field and keep only its leading numeric-dotted run before parsing.
func parseGitVersion(raw string) (*semver.Version, error) {
	fields := strings.Fields(raw)
	if len(fields) < 3 {
		return nil, fmt.Errorf("malformed git version: %q", raw)
	}

	core := strings.TrimRight(leadingVersionCore(fields[2]), ".")
	v, err := semver.NewVersion(core)
	if err != nil {
		return nil, fmt.Errorf("malformed git version %q: %w", raw, err)
	}
	return v, nil
}

// leadingVersionCore returns the leading run of digits and dots in s, dropping
// any vendor suffix (e.g. "2.45.1.macos.1" -> "2.45.1.").
func leadingVersionCore(s string) string {
	i := 0
	for i < len(s) && (s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	return s[:i]
}

// isUnder reports whether path lives at or beneath dir.
func isUnder(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}

	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
