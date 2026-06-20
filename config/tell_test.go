package config

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeUserMain writes a main sesam.yml with one user, one group and one
// secret, and returns its path.
func writeUserMain(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "sesam.yml")
	const body = `users:
  - name: axolotl
    key:
      - keyA
groups:
  admin:
    - axolotl
secrets:
  - path: existing.txt
    access:
      - admin
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

// loadUsersGroups reloads main and returns user names plus the group map.
func loadUsersGroups(t *testing.T, main string) ([]string, map[string][]string) {
	t.Helper()
	cr, err := Load(main)
	require.NoError(t, err)

	users, err := cr.Users()
	require.NoError(t, err)

	var names []string
	for _, u := range users {
		names = append(names, u.Name)
	}
	sort.Strings(names)

	groups, err := cr.Groups()
	require.NoError(t, err)

	return names, groups
}

// TestTell_AddsUserAndGroups adds a user, joining an existing group and a new
// one. Existing entries are preserved, not duplicated.
func TestTell_AddsUserAndGroups(t *testing.T) {
	dir := t.TempDir()
	main := writeUserMain(t, dir)

	cr, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr.Tell("bob", []string{"keyB"}, []string{"admin", "dev"}))
	require.NoError(t, cr.Save())

	names, groups := loadUsersGroups(t, main)
	require.Equal(t, []string{"axolotl", "bob"}, names)
	require.Equal(t, []string{"axolotl", "bob"}, groups["admin"])
	require.Equal(t, []string{"bob"}, groups["dev"])
}

// TestTell_NoDuplicateOnResave verifies that loading and saving again (without
// any change) does not duplicate the existing users or group members — the
// origin-node tracking is what prevents re-appending.
func TestTell_NoDuplicateOnResave(t *testing.T) {
	dir := t.TempDir()
	main := writeUserMain(t, dir)

	cr, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr.Tell("bob", []string{"keyB"}, []string{"admin"}))
	require.NoError(t, cr.Save())

	// Reload and save again with no changes.
	cr2, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr2.Save())

	names, groups := loadUsersGroups(t, main)
	require.Equal(t, []string{"axolotl", "bob"}, names)
	require.Equal(t, []string{"axolotl", "bob"}, groups["admin"])
}

// TestTell_DuplicateUserErrors rejects adding a user that already exists.
func TestTell_DuplicateUserErrors(t *testing.T) {
	dir := t.TempDir()
	main := writeUserMain(t, dir)

	cr, err := Load(main)
	require.NoError(t, err)
	require.Error(t, cr.Tell("axolotl", []string{"keyX"}, []string{"admin"}))
}

// TestTell_CreatesUsersAndGroups handles a main file that has no users: or
// groups: section yet — both are created.
func TestTell_CreatesUsersAndGroups(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	const body = "version: 1\nsecrets:\n  - path: existing.txt\n    access:\n      - admin\n"
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))

	cr, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr.Tell("bob", []string{"keyB"}, []string{"admin"}))
	require.NoError(t, cr.Save())

	names, groups := loadUsersGroups(t, main)
	require.Equal(t, []string{"bob"}, names)
	require.Equal(t, []string{"bob"}, groups["admin"])
}

// TestTell_PreservesUserKeys keeps each user's keys intact through a round trip.
func TestTell_PreservesUserKeys(t *testing.T) {
	dir := t.TempDir()
	main := writeUserMain(t, dir)

	cr, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr.Tell("bob", []string{"keyB1", "keyB2"}, []string{"admin"}))
	require.NoError(t, cr.Save())

	cr2, err := Load(main)
	require.NoError(t, err)

	users, err := cr2.Users()
	require.NoError(t, err)

	keysByName := map[string][]string{}
	for _, u := range users {
		keysByName[u.Name] = u.Key
	}
	require.Equal(t, []string{"keyA"}, keysByName["axolotl"])
	require.Equal(t, []string{"keyB1", "keyB2"}, keysByName["bob"])
}
