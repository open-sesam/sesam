package repo

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"opensesam.org/sesam/core"
)

// RunOptions contains canonical sesam-relative selectors for sesam run.
type RunOptions struct {
	Secrets  []RunSecret
	EnvFiles []string
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

type runEntry struct {
	name  string
	value []byte
}

type runRevealFunc func(path string) ([]byte, error)

const (
	runMaxSelectorPlaintext = core.MaxInMemorySecretSize
	runMaxTotalPlaintext    = 64 * 1024
	runMaxValueSize         = 64 * 1024
	runMaxInjectedSize      = 64 * 1024
	runMaxInjectedVars      = 256
	runMaxProcessSize       = 96 * 1024
)

// PrepareRun reads selected encrypted objects without revealing worktree files.
func (v *View) PrepareRun(opts RunOptions) (*RunPreparation, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}
	return prepareRun(opts, v.secret.RevealSecretBytes)
}

// Environment binds file paths to explicit names and validates the complete
// child environment without changing the caller's environment.
func (p *RunPreparation) Environment(inherited, arguments, filePaths []string) ([]string, error) {
	if len(arguments) == 0 || arguments[0] == "" {
		return nil, fmt.Errorf("a command is required after --")
	}
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
		if bytes.IndexByte(entry.value, 0) >= 0 {
			return fmt.Errorf("value for %s contains NUL", source)
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
	if size := runProcessSize(arguments, env); size > runMaxProcessSize {
		return nil, fmt.Errorf("command arguments and environment require %d bytes, exceeding %d-byte budget", size, runMaxProcessSize)
	}
	return env, nil
}

func prepareRun(opts RunOptions, reveal runRevealFunc) (*RunPreparation, error) {
	if len(opts.Secrets)+len(opts.EnvFiles) == 0 {
		return nil, fmt.Errorf("at least one --secret or --env-file is required")
	}
	if err := validateRunSelectors(opts.Secrets, opts.EnvFiles); err != nil {
		return nil, err
	}

	prepared := &RunPreparation{}
	totalPlaintext := 0
	read := func(path string) ([]byte, error) {
		plaintext, err := reveal(path)
		if err != nil {
			return nil, err
		}
		if len(plaintext) > runMaxSelectorPlaintext {
			return nil, fmt.Errorf("selector %s exceeds %d bytes", path, runMaxSelectorPlaintext)
		}
		totalPlaintext += len(plaintext)
		if totalPlaintext > runMaxTotalPlaintext {
			return nil, fmt.Errorf("total decrypted selector plaintext exceeds %d bytes", runMaxTotalPlaintext)
		}
		return plaintext, nil
	}

	for _, secret := range opts.Secrets {
		value, err := read(secret.Path)
		if err != nil {
			return nil, fmt.Errorf("read secret %s: %w", secret.Path, err)
		}
		prepared.Files = append(prepared.Files, RunFile{Name: secret.Name, Content: value})
	}

	for _, path := range opts.EnvFiles {
		document, err := read(path)
		if err != nil {
			return nil, fmt.Errorf("read env file %s: %w", path, err)
		}
		entries, err := parseDotenv(document)
		if err != nil {
			return nil, fmt.Errorf("parse env file %s: %w", path, err)
		}
		prepared.entries = append(prepared.entries, entries...)
	}

	return prepared, nil
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
			return fmt.Errorf("path %q selected as both secret and env file", path)
		}
		seen[path] = mode
		return nil
	}

	for _, secret := range secrets {
		if secret.Name == "" || !isDotenvNameStart(secret.Name[0]) {
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

	seen := make(map[string]bool)
	var entries []runEntry
	for idx, rawLine := range bytes.Split(document, []byte{'\n'}) {
		lineNumber := idx + 1
		line := rawLine
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		line = trimLeftHorizontal(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if len(line) > len("export") && bytes.Equal(line[:len("export")], []byte("export")) && isHorizontal(line[len("export")]) {
			line = trimLeftHorizontal(line[len("export"):])
		}
		if len(line) == 0 || !isDotenvNameStart(line[0]) {
			return nil, fmt.Errorf("line %d: invalid variable name", lineNumber)
		}

		nameEnd := 1
		for nameEnd < len(line) && isDotenvNameByte(line[nameEnd]) {
			nameEnd++
		}
		name := string(line[:nameEnd])
		line = trimLeftHorizontal(line[nameEnd:])
		if len(line) == 0 || line[0] != '=' {
			return nil, fmt.Errorf("line %d: expected '=' after variable name", lineNumber)
		}

		valueText := trimLeftHorizontal(line[1:])
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
			if len(trimHorizontal(valueText[closing+1:])) != 0 {
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

		if seen[name] {
			return nil, fmt.Errorf("line %d: duplicate variable %q", lineNumber, name)
		}
		seen[name] = true
		entries = append(entries, runEntry{name: name, value: value})
	}

	return entries, nil
}

func isHorizontal(b byte) bool {
	return b == ' ' || b == '\t'
}

func trimLeftHorizontal(value []byte) []byte {
	for len(value) > 0 && isHorizontal(value[0]) {
		value = value[1:]
	}
	return value
}

func trimRightHorizontal(value []byte) []byte {
	for len(value) > 0 && isHorizontal(value[len(value)-1]) {
		value = value[:len(value)-1]
	}
	return value
}

func trimHorizontal(value []byte) []byte {
	return trimRightHorizontal(trimLeftHorizontal(value))
}

func isDotenvNameStart(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b == '_'
}

func isDotenvNameByte(b byte) bool {
	return isDotenvNameStart(b) || b >= '0' && b <= '9'
}

func runProcessSize(arguments, environment []string) int {
	size := (len(arguments) + len(environment) + 2) * int(unsafe.Sizeof(uintptr(0)))
	for _, argument := range arguments {
		size += len(argument) + 1
	}
	for _, entry := range environment {
		size += len(entry) + 1
	}
	return size
}
