package repo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

// RunOptions contains canonical sesam-relative selectors for sesam run.
type RunOptions struct {
	All         bool
	Secrets     []RunSecret
	EnvFiles    []string
	EnvPatterns []string
}

type RunSecret struct {
	Name string
	Path string
}

type RunFile struct {
	Name    string
	Content []byte
}

// RunPreparation holds verified file contents and parsed dotenv entries.
type RunPreparation struct {
	Files   []RunFile
	entries []runEntry
}

// RunCommand is the process Run starts: a resolved executable, its arguments,
// and the environment to inherit.
type RunCommand struct {
	Path string
	Args []string
	Env  []string
}

// ExitError carries how a command started by Run terminated so that the
// caller can reproduce that status. Exactly one of Code and Signal is set.
type ExitError struct {
	Code   int
	Signal syscall.Signal
}

type runEntry struct {
	name  string
	value []byte
}

type runRevealFunc func(path string) ([]byte, error)

type boundedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

const (
	runMaxSelectorPlaintext = 64 * 1024
	runMaxTotalPlaintext    = 64 * 1024
	runMaxValueSize         = 64 * 1024
	runMaxInjectedSize      = 64 * 1024
	runMaxInjectedVars      = 256
)

// PrepareRun reads selected encrypted objects without revealing worktree files.
func (v *View) PrepareRun(opts RunOptions) (*RunPreparation, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}
	if opts.All {
		selected := make(map[string]bool)
		for _, secret := range opts.Secrets {
			selected[secret.Path] = true
		}
		for _, path := range opts.EnvFiles {
			selected[path] = true
		}
		var paths []string
		for _, secret := range v.vstate.Secrets {
			if !selected[secret.RevealedPath] && v.vstate.UserHasAccess(v.whoami, secret.AccessGroups) {
				paths = append(paths, secret.RevealedPath)
			}
		}
		sort.Strings(paths)
		opts.Secrets = append([]RunSecret(nil), opts.Secrets...)
		for _, path := range paths {
			opts.Secrets = append(opts.Secrets, RunSecret{Path: path})
		}
	}
	return prepareRun(opts, func(path string) ([]byte, error) {
		dst := &boundedBuffer{limit: runMaxSelectorPlaintext}
		if err := v.secret.Reveal(path, dst); err != nil {
			return nil, err
		}
		if dst.overflow {
			return nil, fmt.Errorf("secret %s exceeds %d bytes", path, runMaxSelectorPlaintext)
		}
		return dst.buf.Bytes(), nil
	})
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		_, _ = b.buf.Write(p[:min(len(p), remaining)])
	}
	if len(p) > remaining {
		b.overflow = true
	}
	return len(p), nil
}

// Environment binds file paths to explicit names and validates the complete
// child environment without changing the caller's environment.
func (p *RunPreparation) Environment(inherited, filePaths []string) ([]string, error) {
	if len(filePaths) != len(p.Files) {
		return nil, fmt.Errorf("expected %d secret file paths, got %d", len(p.Files), len(filePaths))
	}

	env := append([]string(nil), inherited...)
	owners := make(map[string]string, len(env))
	for _, encoded := range env {
		name, _, _ := strings.Cut(encoded, "=")
		owners[name] = "inherited environment"
	}

	injectedSize := 0
	injectedVars := 0
	add := func(entry runEntry, source string) error {
		if len(entry.value) > runMaxValueSize {
			return fmt.Errorf("value for %s exceeds %d bytes", source, runMaxValueSize)
		}
		if previous, exists := owners[entry.name]; exists {
			return fmt.Errorf("environment variable %q from %s collides with %s", entry.name, source, previous)
		}
		if injectedVars == runMaxInjectedVars {
			return fmt.Errorf("injected environment exceeds %d variables", runMaxInjectedVars)
		}

		encoded := entry.name + "=" + string(entry.value)
		if injectedSize+len(encoded) > runMaxInjectedSize {
			return fmt.Errorf("encoded injected environment exceeds %d bytes", runMaxInjectedSize)
		}

		owners[entry.name] = source
		env = append(env, encoded)
		injectedSize += len(encoded)
		injectedVars++
		return nil
	}

	for i, file := range p.Files {
		if err := add(runEntry{name: file.Name, value: []byte(filePaths[i])}, fmt.Sprintf("file secret %q", file.Name)); err != nil {
			return nil, err
		}
	}
	for _, entry := range p.entries {
		if err := add(entry, "env file"); err != nil {
			return nil, err
		}
	}
	return env, nil
}

// Run starts the command with file secrets as inherited descriptors and dotenv
// entries in its environment, forwards signals, and waits for it. Close the
// repository first: the command may run for hours and may call sesam itself.
func (p *RunPreparation) Run(ctx context.Context, command RunCommand) error {
	filePaths := make([]string, len(p.Files))
	for i := range filePaths {
		filePaths[i] = fmt.Sprintf("/dev/fd/%d", 3+i)
	}
	env, err := p.Environment(command.Env, filePaths)
	if err != nil {
		return err
	}

	files := make([]*os.File, 0, len(p.Files))
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	for _, secret := range p.Files {
		file, err := runSecretFile(secret.Content)
		if err != nil {
			return fmt.Errorf("prepare file secret %q: %w", secret.Name, err)
		}
		files = append(files, file)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGTERM)
	defer signal.Stop(signals)

	child := exec.Cmd{
		Path:       command.Path,
		Args:       command.Args,
		Env:        env,
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		ExtraFiles: files,
	}
	if err := child.Start(); err != nil {
		return fmt.Errorf("exec command %q: %w", command.Args[0], err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	cancelled := ctx.Done()
	for {
		select {
		case err := <-done:
			return commandStatus(command.Args[0], err)
		case received := <-signals:
			// The terminal delivers SIGINT and SIGQUIT to the whole process group,
			// so the child already has them; forwarding would deliver them twice.
			if received != syscall.SIGINT && received != syscall.SIGQUIT {
				_ = child.Process.Signal(received)
			}
		case <-cancelled:
			_ = child.Process.Signal(syscall.SIGTERM)
			cancelled = nil
		}
	}
}

func (e *ExitError) Error() string {
	if e.Signal != 0 {
		return fmt.Sprintf("command terminated by signal %d (%s)", e.Signal, e.Signal)
	}
	return fmt.Sprintf("command exited with status %d", e.Code)
}

// ExitCode uses the shell convention of 128+signal for signaled commands.
func (e *ExitError) ExitCode() int {
	if e.Signal != 0 {
		return 128 + int(e.Signal)
	}
	return e.Code
}

func prepareRun(opts RunOptions, reveal runRevealFunc) (*RunPreparation, error) {
	secrets, err := resolveRunSelectors(opts)
	if err != nil {
		return nil, err
	}

	prepared := &RunPreparation{}
	totalPlaintext := 0
	for _, secret := range secrets {
		value, err := readRunSecret(secret.Path, reveal, &totalPlaintext)
		if err != nil {
			return nil, fmt.Errorf("read secret %s: %w", secret.Path, err)
		}
		if secret.Name != "" {
			prepared.Files = append(prepared.Files, RunFile{Name: secret.Name, Content: value})
		} else if err := prepared.addEnvFile(secret.Path, value); err != nil {
			return nil, err
		}
	}
	for _, path := range opts.EnvFiles {
		document, err := readRunSecret(path, reveal, &totalPlaintext)
		if err != nil {
			return nil, fmt.Errorf("read env file %s: %w", path, err)
		}
		if err := prepared.addEnvFile(path, document); err != nil {
			return nil, err
		}
	}
	return prepared, nil
}

func resolveRunSelectors(opts RunOptions) ([]RunSecret, error) {
	if len(opts.Secrets)+len(opts.EnvFiles) == 0 {
		if opts.All {
			return nil, fmt.Errorf("no accessible secrets selected")
		}
		return nil, fmt.Errorf("at least one --secret, --env-file, or --all is required")
	}
	if err := validateRunSelectors(opts.Secrets, opts.EnvFiles); err != nil {
		return nil, err
	}
	patterns := make([]*regexp.Regexp, 0, len(opts.EnvPatterns))
	for _, pattern := range opts.EnvPatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid env pattern %q: %w", pattern, err)
		}
		patterns = append(patterns, compiled)
	}
	isEnvFile := func(path string) bool {
		if strings.HasSuffix(path, ".env") {
			return true
		}
		for _, pattern := range patterns {
			if pattern.MatchString(filepath.ToSlash(path)) {
				return true
			}
		}
		return false
	}

	secrets := append([]RunSecret(nil), opts.Secrets...)
	for i, secret := range secrets {
		if secret.Name == "" && !isEnvFile(secret.Path) {
			secrets[i].Name = runSecretName(secret.Path)
		}
	}
	return secrets, nil
}

func readRunSecret(path string, reveal runRevealFunc, totalPlaintext *int) ([]byte, error) {
	plaintext, err := reveal(path)
	if err != nil {
		return nil, err
	}
	if len(plaintext) > runMaxSelectorPlaintext {
		return nil, fmt.Errorf("selector %s exceeds %d bytes", path, runMaxSelectorPlaintext)
	}
	*totalPlaintext += len(plaintext)
	if *totalPlaintext > runMaxTotalPlaintext {
		return nil, fmt.Errorf("total decrypted selector plaintext exceeds %d bytes", runMaxTotalPlaintext)
	}
	return plaintext, nil
}

func (p *RunPreparation) addEnvFile(path string, document []byte) error {
	entries, err := parseDotenv(document)
	if err != nil {
		return fmt.Errorf("parse env file %s: %w", path, err)
	}
	p.entries = append(p.entries, entries...)
	return nil
}

func runSecretName(path string) string {
	return "SESAM_" + strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, filepath.ToSlash(path))
}

func validateRunSelectors(secrets []RunSecret, envFiles []string) error {
	seen := make(map[string]string, len(secrets)+len(envFiles))
	check := func(path, mode string) error {
		if path == "" || path == "." || filepath.IsAbs(path) || filepath.Clean(path) != path || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%s selector %q is not a canonical sesam-relative file path", mode, path)
		}
		if previous, exists := seen[path]; exists {
			if previous == mode {
				return fmt.Errorf("duplicate %s selector %q", mode, path)
			}
			return fmt.Errorf("path %q selected as both %s and %s", path, previous, mode)
		}
		seen[path] = mode
		return nil
	}

	for _, secret := range secrets {
		if secret.Name != "" && !isDotenvNameStart(secret.Name[0]) {
			return fmt.Errorf("invalid secret variable name %q", secret.Name)
		}
		for i := 1; i < len(secret.Name); i++ {
			if !isDotenvNameByte(secret.Name[i]) {
				return fmt.Errorf("invalid secret variable name %q", secret.Name)
			}
		}
		if err := check(secret.Path, "secret"); err != nil {
			return err
		}
	}
	for _, path := range envFiles {
		if err := check(path, "env file"); err != nil {
			return err
		}
	}
	return nil
}

func parseDotenv(document []byte) ([]runEntry, error) {
	for i, b := range document {
		if b == '\r' && (i+1 == len(document) || document[i+1] != '\n') {
			return nil, fmt.Errorf("carriage return not followed by newline")
		}
	}

	seen := make(map[string]int)
	var entries []runEntry
	for idx, rawLine := range bytes.Split(document, []byte{'\n'}) {
		lineNumber := idx + 1
		line := rawLine
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		line = bytes.TrimLeft(line, " \t")
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if len(line) > len("export") && bytes.Equal(line[:len("export")], []byte("export")) && isHorizontal(line[len("export")]) {
			line = bytes.TrimLeft(line[len("export"):], " \t")
		}
		if len(line) == 0 || !isDotenvNameStart(line[0]) {
			return nil, fmt.Errorf("line %d: invalid variable name", lineNumber)
		}

		nameEnd := 1
		for nameEnd < len(line) && isDotenvNameByte(line[nameEnd]) {
			nameEnd++
		}
		name := string(line[:nameEnd])
		line = bytes.TrimLeft(line[nameEnd:], " \t")
		if len(line) == 0 || line[0] != '=' {
			return nil, fmt.Errorf("line %d: expected '=' after variable name", lineNumber)
		}

		valueText := bytes.TrimLeft(line[1:], " \t")
		var value []byte
		switch {
		case len(valueText) == 0:
			value = []byte{}
		case valueText[0] == '\'' || valueText[0] == '"':
			quote := valueText[0]
			closing := bytes.IndexByte(valueText[1:], quote)
			if closing < 0 {
				return nil, fmt.Errorf("line %d: unterminated quoted value", lineNumber)
			}
			closing++
			if len(bytes.Trim(valueText[closing+1:], " \t")) != 0 {
				return nil, fmt.Errorf("line %d: unexpected bytes after quoted value", lineNumber)
			}
			value = valueText[1:closing]
		default:
			value = valueText
			for _, b := range value {
				if isHorizontal(b) || b == '\'' || b == '"' || b == '\\' || b == '#' {
					return nil, fmt.Errorf("line %d: invalid byte in unquoted value", lineNumber)
				}
			}
		}

		if previous, exists := seen[name]; exists {
			slog.Warn("duplicate dotenv variable; using last value", slog.String("name", name), slog.Int("line", lineNumber))
			entries[previous].value = value
			continue
		}
		seen[name] = len(entries)
		entries = append(entries, runEntry{name: name, value: value})
	}

	return entries, nil
}

func isHorizontal(b byte) bool {
	return b == ' ' || b == '\t'
}

func isDotenvNameStart(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b == '_'
}

func isDotenvNameByte(b byte) bool {
	return isDotenvNameStart(b) || b >= '0' && b <= '9'
}

// commandStatus translates the result of waiting into an ExitError describing
// how the command terminated, or into a plain error if waiting itself failed.
func commandStatus(name string, waitErr error) error {
	if waitErr == nil {
		return nil
	}

	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		return fmt.Errorf("wait for command %q: %w", name, waitErr)
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return &ExitError{Signal: status.Signal()}
	}
	return &ExitError{Code: exitErr.ExitCode()}
}
