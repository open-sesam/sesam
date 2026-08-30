package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
)

func TestResolveGroups(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		required bool
		want     []string
		additive bool
		wantErr  string
	}{
		{name: "group replaces", args: []string{"cmd", "-g", "dev", "-g", "ops"}, want: []string{"dev", "ops"}},
		{name: "group-add is additive", args: []string{"cmd", "-G", "ops"}, want: []string{"ops"}, additive: true},
		{name: "both flags conflict", args: []string{"cmd", "-g", "dev", "-G", "ops"}, wantErr: "mutually exclusive"},
		{name: "required but neither given", args: []string{"cmd"}, required: true, wantErr: "need --group"},
		{name: "optional and neither given", args: []string{"cmd"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				gotGroups   []string
				gotAdditive bool
				gotErr      error
			)
			cmd := &cli.Command{
				Name: "cmd",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{Name: "group", Aliases: []string{"g"}},
					&cli.StringSliceFlag{Name: "group-add", Aliases: []string{"G"}},
				},
				Action: func(_ context.Context, cmd *cli.Command) error {
					gotGroups, gotAdditive, gotErr = resolveGroups(cmd, tc.required)
					return nil
				},
			}
			require.NoError(t, cmd.Run(context.Background(), tc.args))

			if tc.wantErr != "" {
				require.ErrorContains(t, gotErr, tc.wantErr)
				return
			}
			require.NoError(t, gotErr)
			require.Equal(t, tc.additive, gotAdditive)
			require.Equal(t, tc.want, gotGroups)
		})
	}
}

func TestAskpassRequired(t *testing.T) {
	t.Setenv("SESAM_ASKPASS_REQUIRED", "")
	t.Setenv("GIT_ASKPASS_REQUIRED", "")
	t.Setenv("SSH_ASKPASS_REQUIRED", "")
	require.Equal(t, "prefer", askpassRequired())

	t.Setenv("SSH_ASKPASS_REQUIRED", "force")
	require.Equal(t, "force", askpassRequired())

	t.Setenv("GIT_ASKPASS_REQUIRED", "never")
	require.Equal(t, "never", askpassRequired())

	t.Setenv("SESAM_ASKPASS_REQUIRED", "prefer")
	require.Equal(t, "prefer", askpassRequired())
}

// snakeCase matches the field naming every `--json` payload must use.
var snakeCase = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// jsonSurrogates maps types with a custom MarshalJSON to the struct they
// actually emit, so the walk can keep checking through them.
var jsonSurrogates = map[reflect.Type]reflect.Type{
	reflect.TypeFor[core.Recipient](): reflect.TypeFor[core.UserPubKey](),
}

// TestJSONOutputIsSnakeCase walks every type reachable from a `--json` code
// path and fails on any field that does not serialize as snake_case. Adding a
// PascalCase field anywhere below these roots breaks the machine-readable
// output contract, which is easy to do by accident since Go's default is the
// field name itself.
func TestJSONOutputIsSnakeCase(t *testing.T) {
	roots := []struct {
		command string
		typ     reflect.Type
	}{
		{command: "ls --json", typ: reflect.TypeFor[[]repo.SecretInfo]()},
		{command: "user list --json", typ: reflect.TypeFor[[]repo.UserInfo]()},
		{command: "id --json", typ: reflect.TypeFor[repo.UserInfo]()},
		{command: "verify --json", typ: reflect.TypeFor[repo.VerifyReport]()},
		{command: "status --json", typ: reflect.TypeFor[repo.Status]()},
		{command: "log --json", typ: reflect.TypeFor[core.AuditEntrySigned]()},
	}

	for _, root := range roots {
		t.Run(root.command, func(t *testing.T) {
			for _, bad := range findNonSnakeCaseFields(root.typ, map[reflect.Type]bool{}, "") {
				t.Errorf("%s serializes %s; use a snake_case json tag", root.command, bad)
			}
		})
	}
}

// findNonSnakeCaseFields returns a "path.Field" description for every field
// below typ whose JSON key is not snake_case.
func findNonSnakeCaseFields(typ reflect.Type, seen map[reflect.Type]bool, path string) []string {
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Map {
		typ = typ.Elem()
	}

	if surrogate, ok := jsonSurrogates[typ]; ok {
		typ = surrogate
	} else if typ.Kind() != reflect.Struct ||
		typ.Implements(reflect.TypeFor[json.Marshaler]()) ||
		reflect.PointerTo(typ).Implements(reflect.TypeFor[json.Marshaler]()) {
		// Anything with its own marshaller (time.Time, json.RawMessage,
		// SecretState) decides its own shape; treat it as a leaf.
		return nil
	}

	if seen[typ] {
		return nil
	}
	seen[typ] = true

	var bad []string
	for field := range typ.NumField() {
		f := typ.Field(field)
		if !f.IsExported() {
			continue
		}

		tag, hasTag := f.Tag.Lookup("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}

		// An embedded struct without a name is inlined into the parent object.
		if f.Anonymous && name == "" {
			bad = append(bad, findNonSnakeCaseFields(f.Type, seen, path)...)
			continue
		}

		if name == "" {
			name = f.Name
		}

		if !snakeCase.MatchString(name) {
			missing := ""
			if !hasTag {
				missing = " (no json tag)"
			}
			bad = append(bad, fmt.Sprintf("%s%s as %q%s", path, f.Name, name, missing))
		}

		bad = append(bad, findNonSnakeCaseFields(f.Type, seen, path+f.Name+".")...)
	}

	return bad
}
