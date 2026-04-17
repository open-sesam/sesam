package commands

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"filippo.io/age"
	"github.com/google/renameio"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

//go:embed assets/gitignore.default
var gitignoreTemplate string

//go:embed assets/gitattributes.default
var gitattributesTemplate string

//go:embed assets/pre-commit_hook.default
var preCommitHookTemplate string

//go:embed assets/Readme.default
var sesamReadmeTemplate string

//go:embed assets/secret.example
var exampleSecretContent string

//go:embed assets/config.default
var configTemplate string

// HandleInit bootstraps sesam metadata in a git repository.
func HandleInit(ctx context.Context, cmd *cli.Command) error {
	// NOTE: This init workflow only works well if the repo contains only secrets and nothing else.
	// TODO: We need to discuss how we want to handle it when sesam is initialized in an existing repo.
	// My suggestion would be to have a `secrets/` folder where all secrets are stored,
	// and a `.sesam/` folder for sesam internals.
	//
	// - `.sesam/.gitattributes` for `.sesam/objects/** filter=sesam diff=sesam`
	// - `.sesam/.gitignore` for `.sesam/tmp/`, local helper files, etc.
	// - `secrets/.gitignore` if plaintext secrets should stay only in that folder and never be committed.
	//
	// - `repo/.git/hooks` must stay at repo level, because hooks cannot live in subdirs.
	//   It is important to check if hooks already exist before writing pre-commit,
	//   so we do not overwrite existing hooks and only append the sesam hook at the end.

	repoRoot, err := resolveRepoRoot(cmd.String("repo"))
	if err != nil {
		return err
	}

	if err := ensureNotInitialized(repoRoot); err != nil {
		return err
	}

	initialUser := strings.TrimSpace(cmd.String("user"))
	if initialUser == "" {
		return fmt.Errorf("failed to determine initial user, please pass --user")
	}

	identities, err := loadIdentities(cmd.String("identity"), "sesam.id."+initialUser)
	if err != nil {
		return err
	}

	selectedIdentity, err := chooseInitIdentity(identities, cmd.String("identity"), os.Stdin, os.Stdout, isInteractiveInput(os.Stdin))
	if err != nil {
		return err
	}

	initialRecipient, recipientText, err := resolveInitialRecipient(ctx, cmd.String("recipient"), repoRoot, selectedIdentity)
	if err != nil {
		return err
	}

	if err := ensureSesamDirs(repoRoot); err != nil {
		return err
	}

	configPath := resolveConfigPath(repoRoot, cmd.String("config"))
	if err := createInitialConfig(configPath, initialUser, recipientText); err != nil {
		return err
	}

	if err := ensureInitialSignKey(repoRoot, initialUser, initialRecipient); err != nil {
		return err
	}

	mgr, err := buildInitialSecretManager(
		repoRoot,
		initialUser,
		recipientText,
		selectedIdentity,
	)
	if err != nil {
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

	if err := ensureExampleSecret(repoRoot); err != nil {
		return err
	}

	if err := mgr.AddOrChangeSecret("example.secret", []string{"admin"}); err != nil {
		return fmt.Errorf("failed to bootstrap example secret: %w", err)
	}

	if err := ensureSesamReadme(repoRoot); err != nil {
		return err
	}

	if err := stageInitFiles(repoRoot, configPath); err != nil {
		return err
	}

	return nil
}

// resolveRepoRoot validates the repo input path from the user and requires .git at that path.
func resolveRepoRoot(repoPath string) (string, error) {
	if strings.TrimSpace(repoPath) == "" {
		repoPath = "."
	}

	absRepoPath, err := filepath.Abs(repoPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve repo path %q: %w", repoPath, err)
	}

	repoInfo, err := os.Stat(absRepoPath)
	if err != nil {
		return "", fmt.Errorf("failed to access repo path %s: %w", absRepoPath, err)
	}

	if !repoInfo.IsDir() {
		return "", fmt.Errorf("repo path %s is not a directory", absRepoPath)
	}

	_, err = resolveGitDir(absRepoPath)
	if err != nil {
		return "", fmt.Errorf("no git repository found at %s: %w", absRepoPath, err)
	}

	return absRepoPath, nil
}

// ensureNotInitialized rejects re-running init on a configured repository.
func ensureNotInitialized(repoRoot string) error {
	configPath := filepath.Join(repoRoot, "sesam.yml")
	sesamDir := filepath.Join(repoRoot, ".sesam")

	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("repository already has sesam config at %s", configPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access %s: %w", configPath, err)
	}

	if _, err := os.Stat(sesamDir); err == nil {
		return fmt.Errorf("repository already has sesam directory at %s", sesamDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access %s: %w", sesamDir, err)
	}

	return nil
}

// ensureSesamDirs creates required internal sesam directories.
func ensureSesamDirs(repoRoot string) error {
	dirs := []string{
		filepath.Join(repoRoot, ".sesam"),
		filepath.Join(repoRoot, ".sesam", "signkeys"),
		filepath.Join(repoRoot, ".sesam", "tmp"),
		filepath.Join(repoRoot, ".sesam", "bin"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	fmt.Printf("initialized sesam directory at %s\n", filepath.Join(repoRoot, ".sesam"))
	return nil
}

// resolveConfigPath resolves the config path relative to repo root when needed.
func resolveConfigPath(repoRoot, configPath string) string {
	if !filepath.IsAbs(configPath) {
		return filepath.Join(repoRoot, configPath)
	}

	return configPath
}

// resolveInitialRecipient determines the initial admin recipient key.
func resolveInitialRecipient(ctx context.Context, recipientArg string, repoRoot string, identity *core.Identity) (age.Recipient, string, error) {
	recipientArg = strings.TrimSpace(recipientArg)

	var recipients core.Recipients
	if recipientArg != "" {
		rawRecipient, err := core.ResolveRecipient(ctx, repoRoot, recipientArg, core.CacheModeReadWrite)
		if err != nil {
			return nil, "", fmt.Errorf("failed to resolve recipient %q: %w", recipientArg, err)
		}

		// A resolved forge id (for example github:user) may return multiple
		// newline-separated keys. Parse all and then pick one deterministically.
		parsedRecipients, err := parseRecipients(rawRecipient)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse recipient %q: %w", recipientArg, err)
		}

		recipients = append(recipients, parsedRecipients...)
	}

	if len(recipients) > 0 {
		for _, recipient := range recipients {
			if identity.Public().Equal(recipient.ComparablePublicKey) {
				return recipient, recipient.String(), nil
			}
		}

		return nil, "", fmt.Errorf("none of the resolved recipients matches the selected identity")
	}

	recipient, err := core.ParseRecipient(identity.Public().String())
	if err != nil {
		return nil, "", fmt.Errorf("failed to derive recipient from identity: %w", err)
	}

	return recipient, recipient.String(), nil
}

// createInitialConfig writes sesam.yml using the embedded template.
func createInitialConfig(configPath, initialUser, recipientText string) error {
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config already exists at %s", configPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access config path %s: %w", configPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("failed to create config directory for %s: %w", configPath, err)
	}

	quotedUser := quoteYAMLString(initialUser)
	quotedRecipient := quoteYAMLString(recipientText)

	config := fmt.Sprintf(configTemplate, quotedUser, quotedRecipient, quotedUser)

	if err := renameio.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return fmt.Errorf("failed to create sample config %s: %w", configPath, err)
	}

	fmt.Printf("created sample config at %s\n", configPath)
	return nil
}

// quoteYAMLString single-quotes and escapes values for YAML templates.
func quoteYAMLString(value string) string {
	escaped := strings.ReplaceAll(value, "'", "''")
	return "'" + escaped + "'"
}

// chooseInitIdentity selects one identity for init operations.
//
// With multiple identities we require explicit choice in interactive sessions,
// and return an error in non-interactive mode.
func chooseInitIdentity(
	identities core.Identities,
	identityPath string,
	in io.Reader,
	out io.Writer,
	interactive bool,
) (*core.Identity, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("no identities available")
	}

	if len(identities) == 1 {
		return identities[0], nil
	}

	if !interactive {
		return nil, fmt.Errorf(
			"multiple identities found in %s; run init interactively to choose one",
			identityPath,
		)
	}

	fmt.Fprintf(out, "warning: multiple identities found in %s\n", identityPath)
	fmt.Fprintln(out, "choose identity to use for init:")
	for idx, identity := range identities {
		fmt.Fprintf(out, "  [%d] %s\n", idx+1, identity.Public().String())
	}

	reader := bufio.NewReader(in)
	for {
		fmt.Fprint(out, "identity number: ")

		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to read selection: %w", err)
		}

		choice := strings.TrimSpace(line)
		if choice == "" {
			if err == io.EOF {
				return nil, fmt.Errorf("no identity selected")
			}

			fmt.Fprintln(out, "invalid selection: enter a number from the list")
			continue
		}

		idx, convErr := strconv.Atoi(choice)
		if convErr != nil || idx < 1 || idx > len(identities) {
			fmt.Fprintln(out, "invalid selection: enter a number from the list")
			if err == io.EOF {
				return nil, fmt.Errorf("invalid identity selection %q", choice)
			}
			continue
		}

		return identities[idx-1], nil
	}
}

func isInteractiveInput(input *os.File) bool {
	if input == nil {
		return false
	}

	info, err := input.Stat()
	if err != nil {
		return false
	}

	return (info.Mode() & os.ModeCharDevice) != 0
}

// buildInitialSecretManager bootstraps audit/keyring state for init-time actions.
func buildInitialSecretManager(
	repoRoot string,
	initialUser string,
	recipientText string,
	identity *core.Identity,
) (*core.SecretManager, error) {
	signer, err := core.LoadSignKey(repoRoot, initialUser, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to load sign key for %s: %w", initialUser, err)
	}

	signKeyStr := core.MulticodeEncode(signer.PublicKey(), core.MhEd25519Pub)
	auditLog, err := core.InitLog(repoRoot, signer, core.DetailUserTell{
		User:        initialUser,
		Groups:      []string{"admin"},
		PubKeys:     []string{recipientText},
		SignPubKeys: []string{signKeyStr},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init audit log: %w", err)
	}

	if err := auditLog.Store(); err != nil {
		return nil, fmt.Errorf("failed to store audit log: %w", err)
	}

	keyring := core.NewMemoryKeyring()
	vstate, err := core.Verify(auditLog, keyring)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit log: %w", err)
	}

	mgr, err := core.BuildSecretManager(
		repoRoot,
		initialUser,
		core.Identities{identity},
		signer,
		keyring,
		auditLog,
		vstate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build secret manager: %w", err)
	}

	return mgr, nil
}

// ensureInitialSignKey creates encrypted signing key material for initial user.
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

// ensurePublicSignKey writes the plaintext public signing key.
func ensurePublicSignKey(repoRoot, initialUser string, signer core.Signer) error {
	pubPath := filepath.Join(repoRoot, ".sesam", "signkeys", initialUser+".pub")

	if _, err := os.Stat(pubPath); err == nil {
		fmt.Printf("signing public key already exists at %s\n", pubPath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access signing public key %s: %w", pubPath, err)
	}

	if signer == nil {
		return fmt.Errorf("cannot create public signing key at %s without signer", pubPath)
	}

	encodedPublicKey := core.MulticodeEncode(signer.PublicKey(), core.MhEd25519Pub)
	if err := renameio.WriteFile(pubPath, []byte(encodedPublicKey+"\n"), 0o600); err != nil {
		return fmt.Errorf("failed to write signing public key %s: %w", pubPath, err)
	}

	fmt.Printf("created signing public key at %s\n", pubPath)
	return nil
}

// ensureDefaultGitIgnore appends sesam rules to .gitignore.
func ensureDefaultGitIgnore(repoRoot string) error {
	gitignorePath := filepath.Join(repoRoot, ".gitignore")
	return appendMissingLines(gitignorePath, gitignoreTemplate, 0o600)
}

// ensureDefaultGitAttributes appends sesam filter rules to .gitattributes.
func ensureDefaultGitAttributes(repoRoot string) error {
	gitAttributesPath := filepath.Join(repoRoot, ".gitattributes")
	return appendMissingLines(gitAttributesPath, gitattributesTemplate, 0o644)
}

// appendMissingLines appends only lines not already present in a file.
func appendMissingLines(path string, content string, mode os.FileMode) error {
	var existing string
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access %s: %w", path, err)
	}

	b := strings.Builder{}
	b.WriteString(existing)

	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(existing, line+"\n") || strings.HasSuffix(existing, line) {
			continue
		}

		if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteString("\n")
		}

		b.WriteString(line)
		b.WriteString("\n")
	}

	if b.String() == existing {
		return nil
	}

	if err := renameio.WriteFile(path, []byte(b.String()), mode); err != nil {
		return fmt.Errorf("failed to update %s: %w", path, err)
	}

	return nil
}

// ensureVerifyHook installs the default pre-commit verification hook.
func ensureVerifyHook(repoRoot string) error {
	gitDir, err := resolveGitDir(repoRoot)
	if err != nil {
		return fmt.Errorf("no git repository detected at %s: %w", repoRoot, err)
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

	if err := renameio.WriteFile(hookPath, []byte(preCommitHookTemplate), 0o755); err != nil {
		return fmt.Errorf("failed to create pre-commit hook at %s: %w", hookPath, err)
	}

	fmt.Printf("created pre-commit hook at %s\n", hookPath)
	return nil
}

// resolveGitDir resolves both directory and indirection-file .git layouts.
//
// It returns the effective git metadata directory path.
func resolveGitDir(repoRoot string) (string, error) {
	gitPath := filepath.Join(repoRoot, ".git")

	info, err := os.Stat(gitPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("missing .git in %s", repoRoot)
		}

		return "", fmt.Errorf("failed to access git metadata at %s: %w", gitPath, err)
	}

	if info.IsDir() {
		return gitPath, nil
	}

	// In worktrees/submodules .git can be a file that points to the real
	// metadata directory via "gitdir: <path>". Parse that indirection so we
	// install hooks and read metadata from the effective git directory.
	data, err := os.ReadFile(gitPath)
	if err != nil {
		return "", fmt.Errorf("failed to read git metadata at %s: %w", gitPath, err)
	}

	line := strings.TrimSpace(string(data))
	const prefix = "gitdir:"
	if !strings.HasPrefix(strings.ToLower(line), prefix) {
		return "", fmt.Errorf("unsupported .git format in %s", gitPath)
	}

	resolvedPath := strings.TrimSpace(line[len(prefix):])
	if resolvedPath == "" {
		return "", fmt.Errorf("empty gitdir in %s", gitPath)
	}

	if filepath.IsAbs(resolvedPath) {
		return resolvedPath, nil
	}

	return filepath.Clean(filepath.Join(repoRoot, resolvedPath)), nil
}

// ensureGitSesamShim installs a repo-local git-sesam helper.
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
	if err := renameio.WriteFile(shimPath, []byte(script), 0o755); err != nil {
		return fmt.Errorf("failed to create git-sesam shim at %s: %w", shimPath, err)
	}

	fmt.Printf("created git-sesam shim at %s (add .sesam/bin to your PATH)\n", shimPath)
	return nil
}

// ensureExampleSecret creates a starter secret file for first-time usage.
func ensureExampleSecret(repoRoot string) error {
	examplePath := filepath.Join(repoRoot, "example.secret")
	if _, err := os.Stat(examplePath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access %s: %w", examplePath, err)
	}

	if err := renameio.WriteFile(examplePath, []byte(exampleSecretContent), 0o600); err != nil {
		return fmt.Errorf("failed to create example secret %s: %w", examplePath, err)
	}

	fmt.Printf("created example secret at %s\n", examplePath)
	return nil
}

// ensureSesamReadme writes a short onboarding note into .sesam.
func ensureSesamReadme(repoRoot string) error {
	readmePath := filepath.Join(repoRoot, ".sesam", "README.md")
	if _, err := os.Stat(readmePath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access %s: %w", readmePath, err)
	}

	if err := renameio.WriteFile(readmePath, []byte(sesamReadmeTemplate), 0o600); err != nil {
		return fmt.Errorf("failed to create sesam readme %s: %w", readmePath, err)
	}

	fmt.Printf("created sesam readme at %s\n", readmePath)
	return nil
}

// stageInitFiles tries to stage init artifacts with git add.
//
// Failure is non-fatal and reported as warning output.
func stageInitFiles(repoRoot, configPath string) error {
	files := []string{
		filepath.Join(repoRoot, ".sesam"),
		configPath,
		filepath.Join(repoRoot, ".gitignore"),
		filepath.Join(repoRoot, ".gitattributes"),
		filepath.Join(repoRoot, "example.secret"),
	}

	args := append([]string{"add"}, files...)
	cmd := exec.Command("git", args...)
	cmd.Dir = repoRoot

	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("warning: failed to stage init files automatically: %v (%s)\n", err, strings.TrimSpace(string(output)))
		return nil
	}

	return nil
}
