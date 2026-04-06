package commands

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

func HandleInit(ctx context.Context, cmd *cli.Command) error {
	repoPath := cmd.String("repo")
	if repoPath == "" {
		repoPath = "."
	}

	absRepoPath, err := filepath.Abs(repoPath)
	if err != nil {
		return fmt.Errorf("failed to resolve repo path %q: %w", repoPath, err)
	}

	repoInfo, err := os.Stat(absRepoPath)
	if err != nil {
		return fmt.Errorf("failed to access repo path %s: %w", absRepoPath, err)
	}
	if !repoInfo.IsDir() {
		return fmt.Errorf("repo path %s is not a directory", absRepoPath)
	}

	repoRoot, foundGitRoot, err := findGitRoot(absRepoPath)
	if err != nil {
		return err
	}
	if !foundGitRoot {
		repoRoot = absRepoPath
	}

	initialUser := strings.TrimSpace(cmd.String("user"))
	if initialUser == "" {
		initialUser = os.Getenv("USER")
	}
	if initialUser == "" {
		currentUser, err := user.Current()
		if err == nil {
			initialUser = currentUser.Username
		}
	}
	if initialUser == "" {
		return fmt.Errorf("failed to determine initial user, please pass --user")
	}

	initialRecipient, recipientText, err := resolveInitialRecipient(ctx, cmd, repoRoot, initialUser)
	if err != nil {
		return err
	}

	sesamDir := filepath.Join(repoRoot, ".sesam")
	if err := os.MkdirAll(sesamDir, 0o700); err != nil {
		return fmt.Errorf("failed to create sesam directory %s: %w", sesamDir, err)
	}

	signKeyDir := filepath.Join(sesamDir, "signkeys")
	if err := os.MkdirAll(signKeyDir, 0o700); err != nil {
		return fmt.Errorf("failed to create signkey directory %s: %w", signKeyDir, err)
	}

	fmt.Printf("initialized sesam directory at %s\n", sesamDir)

	configPath := cmd.String("config")
	if !filepath.IsAbs(configPath) {
		configPath = filepath.Join(repoRoot, configPath)
	}

	if err := createInitialConfig(configPath, initialUser, recipientText); err != nil {
		return err
	}

	if err := ensureInitialSignKey(repoRoot, initialUser, initialRecipient); err != nil {
		return err
	}

	if err := ensureDefaultGitIgnore(repoRoot); err != nil {
		return err
	}

	if err := ensureDefaultGitAttributes(repoRoot); err != nil {
		return err
	}

	if err := ensureVerifyHook(repoRoot); err != nil {
		return err
	}

	if err := ensureGitSesamShim(repoRoot); err != nil {
		return err
	}

	return nil
}

func findGitRoot(startPath string) (string, bool, error) {
	path := startPath

	for {
		gitPath := filepath.Join(path, ".git")
		if _, err := os.Stat(gitPath); err == nil {
			return path, true, nil
		} else if !os.IsNotExist(err) {
			return "", false, fmt.Errorf("failed to inspect %s: %w", gitPath, err)
		}

		parentPath := filepath.Dir(path)
		if parentPath == path {
			return startPath, false, nil
		}

		path = parentPath
	}
}

func resolveInitialRecipient(ctx context.Context, cmd *cli.Command, repoRoot, initialUser string) (age.Recipient, string, error) {
	recipientArg := strings.TrimSpace(cmd.String("recipient"))
	if recipientArg != "" {
		rawRecipients, err := core.ResolveRecipient(ctx, repoRoot, recipientArg, core.CacheModeReadWrite)
		if err != nil {
			return nil, "", fmt.Errorf("failed to resolve recipient %q: %w", recipientArg, err)
		}

		recipients, err := parseRecipients(rawRecipients)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse recipient %q: %w", recipientArg, err)
		}

		identities, err := loadIdentities(cmd.String("identity"), initialUser)
		if err == nil {
			matchedRecipient, matchErr := matchIdentityRecipient(identities, recipients)
			if matchErr == nil {
				return matchedRecipient, recipientAsString(matchedRecipient), nil
			}
		}

		return recipients[0], recipientAsString(recipients[0]), nil
	}

	identities, err := loadIdentities(cmd.String("identity"), initialUser)
	if err != nil {
		return nil, "", fmt.Errorf("failed to derive recipient from identity: %w", err)
	}

	for _, identity := range identities {
		switch i := identity.(type) {
		case *age.X25519Identity:
			recipient := i.Recipient()
			return recipient, recipientAsString(recipient), nil
		case *age.HybridIdentity:
			recipient := i.Recipient()
			return recipient, recipientAsString(recipient), nil
		case *agessh.Ed25519Identity:
			recipient := i.Recipient()
			return recipient, recipientAsString(recipient), nil
		case *agessh.RSAIdentity:
			recipient := i.Recipient()
			return recipient, recipientAsString(recipient), nil
		}
	}

	return nil, "", fmt.Errorf("unable to derive recipient from identity, pass --recipient")
}

func recipientAsString(recipient age.Recipient) string {
	if stringer, ok := recipient.(fmt.Stringer); ok {
		return stringer.String()
	}

	return ""
}

func createInitialConfig(configPath, initialUser, recipientText string) error {
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("config already exists at %s\n", configPath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access config path %s: %w", configPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("failed to create config directory for %s: %w", configPath, err)
	}

	quotedUser := quoteYAMLString(initialUser)
	quotedRecipient := quoteYAMLString(recipientText)

	config := fmt.Sprintf(`version: 1

config:
  users:
    - name: %s
      key: %s
  groups:
    admin:
      - %s

secrets: []
`, quotedUser, quotedRecipient, quotedUser)

	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return fmt.Errorf("failed to create sample config %s: %w", configPath, err)
	}

	fmt.Printf("created sample config at %s\n", configPath)
	return nil
}

func quoteYAMLString(value string) string {
	escaped := strings.ReplaceAll(value, "'", "''")
	return "'" + escaped + "'"
}

func ensureInitialSignKey(repoRoot, initialUser string, initialRecipient age.Recipient) error {
	signKeyPath := filepath.Join(repoRoot, ".sesam", "signkeys", initialUser+".age")
	if _, err := os.Stat(signKeyPath); err == nil {
		fmt.Printf("signing key already exists at %s\n", signKeyPath)
		return ensurePublicSignKey(repoRoot, initialUser, nil)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access signing key %s: %w", signKeyPath, err)
	}

	signer, err := core.GenerateSignKey(repoRoot, initialUser, initialRecipient)
	if err != nil {
		return fmt.Errorf("failed to generate signing key for %q: %w", initialUser, err)
	}

	fmt.Printf("created encrypted signing key at %s\n", signKeyPath)
	return ensurePublicSignKey(repoRoot, initialUser, signer)
}

func ensurePublicSignKey(repoRoot, initialUser string, signer core.Signer) error {
	pubPath := filepath.Join(repoRoot, ".sesam", "signkeys", initialUser+".pub")
	if _, err := os.Stat(pubPath); err == nil {
		fmt.Printf("signing public key already exists at %s\n", pubPath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access signing public key %s: %w", pubPath, err)
	}

	if signer == nil {
		fmt.Printf("skipping public key write: %s exists but public key is not derivable without decrypting\n", filepath.Join(repoRoot, ".sesam", "signkeys", initialUser+".age"))
		return nil
	}

	encodedPublicKey := core.MulticodeEncode(signer.PublicKey(), core.MhEd25519Pub)
	if err := os.WriteFile(pubPath, []byte(encodedPublicKey+"\n"), 0o600); err != nil {
		return fmt.Errorf("failed to write signing public key %s: %w", pubPath, err)
	}

	fmt.Printf("created signing public key at %s\n", pubPath)
	return nil
}

func ensureDefaultGitIgnore(repoRoot string) error {
	gitignorePath := filepath.Join(repoRoot, ".gitignore")
	if _, err := os.Stat(gitignorePath); err == nil {
		fmt.Printf(".gitignore already exists at %s; leaving unchanged\n", gitignorePath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access .gitignore at %s: %w", gitignorePath, err)
	}

	content := "# Generated by sesam init\n*\n!.sesam/\n!.sesam/**\n!sesam.yml\n!.gitignore\n!.gitattributes\n"
	if err := os.WriteFile(gitignorePath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to create .gitignore at %s: %w", gitignorePath, err)
	}

	fmt.Printf("created .gitignore at %s\n", gitignorePath)
	return nil
}

func ensureDefaultGitAttributes(repoRoot string) error {
	gitAttributesPath := filepath.Join(repoRoot, ".gitattributes")
	if _, err := os.Stat(gitAttributesPath); err == nil {
		fmt.Printf(".gitattributes already exists at %s; leaving unchanged\n", gitAttributesPath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access .gitattributes at %s: %w", gitAttributesPath, err)
	}

	content := "# Generated by sesam init\n.sesam/objects/** filter=sesam diff=sesam\n"
	if err := os.WriteFile(gitAttributesPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to create .gitattributes at %s: %w", gitAttributesPath, err)
	}

	fmt.Printf("created .gitattributes at %s\n", gitAttributesPath)
	return nil
}

func ensureVerifyHook(repoRoot string) error {
	gitDir, found, err := resolveGitDir(repoRoot)
	if err != nil {
		return err
	}
	if !found {
		fmt.Println("no git repository detected; skipping hook setup")
		return nil
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); err == nil {
		fmt.Printf("pre-commit hook already exists at %s; leaving unchanged\n", hookPath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access hook %s: %w", hookPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(hookPath), 0o700); err != nil {
		return fmt.Errorf("failed to create hook directory for %s: %w", hookPath, err)
	}

	script := "#!/bin/sh\nset -eu\nif command -v sesam >/dev/null 2>&1; then\n  sesam verify\nelse\n  git sesam verify\nfi\n"
	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		return fmt.Errorf("failed to create pre-commit hook at %s: %w", hookPath, err)
	}

	fmt.Printf("created pre-commit hook at %s\n", hookPath)
	return nil
}

func resolveGitDir(repoRoot string) (string, bool, error) {
	gitPath := filepath.Join(repoRoot, ".git")

	info, err := os.Stat(gitPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}

		return "", false, fmt.Errorf("failed to access git metadata at %s: %w", gitPath, err)
	}

	if info.IsDir() {
		return gitPath, true, nil
	}

	data, err := os.ReadFile(gitPath)
	if err != nil {
		return "", false, fmt.Errorf("failed to read git metadata at %s: %w", gitPath, err)
	}

	line := strings.TrimSpace(string(data))
	const prefix = "gitdir:"
	if !strings.HasPrefix(strings.ToLower(line), prefix) {
		return "", false, fmt.Errorf("unsupported .git format in %s", gitPath)
	}

	resolvedPath := strings.TrimSpace(line[len(prefix):])
	if resolvedPath == "" {
		return "", false, fmt.Errorf("empty gitdir in %s", gitPath)
	}

	if filepath.IsAbs(resolvedPath) {
		return resolvedPath, true, nil
	}

	return filepath.Clean(filepath.Join(repoRoot, resolvedPath)), true, nil
}

func ensureGitSesamShim(repoRoot string) error {
	shimPath := filepath.Join(repoRoot, ".sesam", "bin", "git-sesam")
	if _, err := os.Stat(shimPath); err == nil {
		fmt.Printf("git-sesam shim already exists at %s\n", shimPath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access git-sesam shim %s: %w", shimPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(shimPath), 0o700); err != nil {
		return fmt.Errorf("failed to create shim directory for %s: %w", shimPath, err)
	}

	script := "#!/bin/sh\nexec sesam \"$@\"\n"
	if err := os.WriteFile(shimPath, []byte(script), 0o755); err != nil {
		return fmt.Errorf("failed to create git-sesam shim at %s: %w", shimPath, err)
	}

	fmt.Printf("created git-sesam shim at %s (add .sesam/bin to your PATH)\n", shimPath)
	return nil
}
