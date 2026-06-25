package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeGroupsMain writes a main sesam.yml where axolotl belongs to admin and
// dev (each with a second member so removals never empty a group), and ops
// holds only bravo. Used to exercise UserChangeGroups add/remove/leave-alone.
func writeGroupsMain(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "sesam.yml")
	const body = `users:
  - name: axolotl
    key:
      - keyA
groups:
  admin:
    - axolotl
    - root
  dev:
    - axolotl
    - bravo
  ops:
    - bravo
secrets:
  - path: existing.txt
    access:
      - admin
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

// TestUserRename_RenamesUser renames a user; the new name replaces the old in
// the users list and survives a round trip.
func TestUserRename_RenamesUser(t *testing.T) {
	dir := t.TempDir()
	main := writeUserMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserRename("axolotl", "newt"))
	require.NoError(t, cr.Save())

	names, _ := loadUsersGroups(t, main)
	require.Equal(t, []string{"newt"}, names)
}

// TestUserRename_TargetsNamedUser renames only the matched user.
func TestUserRename_TargetsNamedUser(t *testing.T) {
	dir := t.TempDir()
	main := writeTwoUserMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserRename("bravo", "newt"))
	require.NoError(t, cr.Save())

	names, _ := loadUsersGroups(t, main)
	require.Equal(t, []string{"axolotl", "newt"}, names)
}

// TestUserRename_PreservesKeys keeps the renamed user's keys intact.
func TestUserRename_PreservesKeys(t *testing.T) {
	dir := t.TempDir()
	main := writeUserMain(t, dir) // axolotl with [keyA]

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserRename("axolotl", "newt"))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"keyA"}, keysByUser(t, main)["newt"])
}

// TestUserRename_UpdatesGroupMembership renames the user inside group lists too,
// so membership doesn't dangle on the old name.
func TestUserRename_UpdatesGroupMembership(t *testing.T) {
	dir := t.TempDir()
	main := writeUserMain(t, dir) // axolotl is a member of group "admin"

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserRename("axolotl", "newt"))
	require.NoError(t, cr.Save())

	_, groups := loadUsersGroups(t, main)
	require.Equal(t, []string{"newt"}, groups["admin"])
}

// TestUserRename_UnknownUserErrors rejects renaming a user that does not exist.
func TestUserRename_UnknownUserErrors(t *testing.T) {
	dir := t.TempDir()
	main := writeTwoUserMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.Error(t, cr.UserRename("ghost", "newt"))
}

// TestUserChangeGroups_AddsToExistingGroup adds the user to a group they are
// not yet in, leaving their other memberships intact.
func TestUserChangeGroups_AddsToExistingGroup(t *testing.T) {
	dir := t.TempDir()
	main := writeGroupsMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserChangeGroups("axolotl", []string{"admin", "dev", "ops"}))
	require.NoError(t, cr.Save())

	_, groups := loadUsersGroups(t, main)
	require.Equal(t, []string{"bravo", "axolotl"}, groups["ops"])
	require.Equal(t, []string{"axolotl", "root"}, groups["admin"])
	require.Equal(t, []string{"axolotl", "bravo"}, groups["dev"])
}

// TestUserChangeGroups_RemovesFromGroup drops the user from a group they should
// no longer be in, leaving the remaining members untouched.
func TestUserChangeGroups_RemovesFromGroup(t *testing.T) {
	dir := t.TempDir()
	main := writeGroupsMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserChangeGroups("axolotl", []string{"admin"}))
	require.NoError(t, cr.Save())

	_, groups := loadUsersGroups(t, main)
	require.Equal(t, []string{"bravo"}, groups["dev"], "axolotl removed, bravo kept")
	require.Equal(t, []string{"axolotl", "root"}, groups["admin"], "kept where still desired")
}

// TestUserChangeGroups_SetsExactMembership adds and removes in one call so the
// user ends up in exactly the requested set.
func TestUserChangeGroups_SetsExactMembership(t *testing.T) {
	dir := t.TempDir()
	main := writeGroupsMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserChangeGroups("axolotl", []string{"ops"}))
	require.NoError(t, cr.Save())

	_, groups := loadUsersGroups(t, main)
	require.Equal(t, []string{"root"}, groups["admin"], "removed from admin")
	require.Equal(t, []string{"bravo"}, groups["dev"], "removed from dev")
	require.Equal(t, []string{"bravo", "axolotl"}, groups["ops"], "added to ops")
}

// TestUserChangeGroups_RemovesEmptiedGroup drops a group entirely when its last
// member is removed — a memberless group is meaningless (and an empty sequence
// would otherwise render as null and fail schema validation).
func TestUserChangeGroups_RemovesEmptiedGroup(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	const body = `users:
  - name: axolotl
    key:
      - keyA
groups:
  admin:
    - axolotl
    - root
  solo:
    - axolotl
secrets:
  - path: existing.txt
    access:
      - admin
`
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserChangeGroups("axolotl", []string{"admin"}))
	require.NoError(t, cr.Save())

	_, groups := loadUsersGroups(t, main)
	_, ok := groups["solo"]
	require.False(t, ok, "a group emptied of its last member must be removed")
	require.Equal(t, []string{"axolotl", "root"}, groups["admin"], "still-desired group untouched")
}

// TestUserChangeGroups_CreatesMissingGroup adds the user to a group that does
// not exist yet; the group should be created with the user as a member.
func TestUserChangeGroups_CreatesMissingGroup(t *testing.T) {
	dir := t.TempDir()
	main := writeGroupsMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserChangeGroups("axolotl", []string{"admin", "dev", "brandnew"}))
	require.NoError(t, cr.Save())

	_, groups := loadUsersGroups(t, main)
	require.Equal(t, []string{"axolotl"}, groups["brandnew"])
}
