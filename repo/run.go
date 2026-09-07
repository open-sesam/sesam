package repo

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"opensesam.org/sesam/core"
)

// RunOptions contains already-canonical selectors and the inherited process
// inputs used to prepare an environment for sesam run.
type RunOptions struct {
	All         bool
	Secrets     []string
	EnvFiles    []string
	Environment []string
	Arguments   []string
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

// PrepareRunEnvironment verifies selected objects and builds a child-only
// environment without mutating the current process.
func (v *View) PrepareRunEnvironment(opts RunOptions) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}
	if opts.All {
		if len(opts.Secrets) > 0 {
			return nil, fmt.Errorf("--all and --secret cannot be used together")
		}
		if err := validateRunSelectors(nil, opts.EnvFiles); err != nil {
			return nil, err
		}

		envFiles := make(map[string]struct{}, len(opts.EnvFiles))
		for _, path := range opts.EnvFiles {
			envFiles[path] = struct{}{}
		}
		secrets := make([]string, 0, len(v.vstate.Secrets))
		for _, secret := range v.vstate.Secrets {
			if _, overridden := envFiles[secret.RevealedPath]; overridden {
				continue
			}
			if v.vstate.UserHasAccess(v.whoami, secret.AccessGroups) {
				secrets = append(secrets, secret.RevealedPath)
			}
		}
		sort.Strings(secrets)
		opts.Secrets = secrets
		if len(opts.Secrets)+len(opts.EnvFiles) == 0 {
			return nil, fmt.Errorf("no secrets accessible to user %s", v.whoami)
		}
		opts.All = false
	}

	return prepareRunEnvironment(opts, v.secret.RevealSecretBytes)
}

func prepareRunEnvironment(opts RunOptions, reveal runRevealFunc) ([]string, error) {
	if len(opts.Secrets)+len(opts.EnvFiles) == 0 {
		return nil, fmt.Errorf("at least one --secret or --env-file is required")
	}
	if len(opts.Arguments) == 0 || opts.Arguments[0] == "" {
		return nil, fmt.Errorf("a command is required after --")
	}
	if err := validateRunSelectors(opts.Secrets, opts.EnvFiles); err != nil {
		return nil, err
	}

	env := append([]string(nil), opts.Environment...)
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

	for _, path := range opts.Secrets {
		value, err := read(path)
		if err != nil {
			return nil, fmt.Errorf("read secret %s: %w", path, err)
		}
		if err := add(runEntry{name: runSecretName(path), value: value}, fmt.Sprintf("secret %q", path)); err != nil {
			return nil, err
		}
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
		for _, entry := range entries {
			if err := add(entry, fmt.Sprintf("env file %q", path)); err != nil {
				return nil, err
			}
		}
	}

	if size := runProcessSize(opts.Arguments, env); size > runMaxProcessSize {
		return nil, fmt.Errorf("command arguments and environment require %d bytes, exceeding %d-byte budget", size, runMaxProcessSize)
	}

	return env, nil
}

func validateRunSelectors(secrets, envFiles []string) error {
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

	for _, path := range secrets {
		if err := check(path, "secret"); err != nil {
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

func runSecretName(path string) string {
	var name strings.Builder
	name.Grow(len("SESAM_SECRET_") + len(path))
	name.WriteString("SESAM_SECRET_")
	for i := 0; i < len(path); i++ {
		b := path[i]
		switch {
		case b >= 'a' && b <= 'z':
			name.WriteByte(b - ('a' - 'A'))
		case b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
			name.WriteByte(b)
		default:
			name.WriteByte('_')
		}
	}
	return name.String()
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
