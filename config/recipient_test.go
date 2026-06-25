package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeTwoUserMain writes a main sesam.yml with two users (each with one key),
// so tests can assert that an operation targets the right one.
func writeTwoUserMain(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "sesam.yml")
	const body = `users:
  - name: axolotl
    key:
      - keyA
  - name: bravo
    key:
      - keyB
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

// keysByUser reloads main and maps each user name to its key list.
func keysByUser(t *testing.T, main string) map[string][]string {
	t.Helper()
	cr, err := loadConfig(t, main)
	require.NoError(t, err)

	users, err := cr.Users()
	require.NoError(t, err)

	m := map[string][]string{}
	for _, u := range users {
		m[u.Name] = u.Key
	}
	return m
}

// writeMultiKeyMain writes a main sesam.yml with two users that each hold
// several keys, so removal can be asserted precisely.
func writeMultiKeyMain(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "sesam.yml")
	const body = `users:
  - name: axolotl
    key:
      - keyA1
      - keyA2
      - keyA3
  - name: bravo
    key:
      - keyB1
      - keyB2
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

// TestUserAddRecipient_AppendsToNamedUser adds a key to a user that already has
// one; it is appended and survives a round trip.
func TestUserAddRecipient_AppendsToNamedUser(t *testing.T) {
	dir := t.TempDir()
	main := writeUserMain(t, dir) // single user "axolotl" with [keyA]

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserAddRecipient("axolotl", []string{"keyZ"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"keyA", "keyZ"}, keysByUser(t, main)["axolotl"])
}

// TestUserAddRecipient_MultipleKeys appends several keys at once.
func TestUserAddRecipient_MultipleKeys(t *testing.T) {
	dir := t.TempDir()
	main := writeUserMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserAddRecipient("axolotl", []string{"k1", "k2"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"keyA", "k1", "k2"}, keysByUser(t, main)["axolotl"])
}

// TestUserAddRecipient_TargetsNamedUser adds a key to the *named* user only;
// the other user's keys must be left untouched.
func TestUserAddRecipient_TargetsNamedUser(t *testing.T) {
	dir := t.TempDir()
	main := writeTwoUserMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserAddRecipient("bravo", []string{"keyZ"}))
	require.NoError(t, cr.Save())

	keys := keysByUser(t, main)
	require.Equal(t, []string{"keyA"}, keys["axolotl"], "untargeted user must be unchanged")
	require.Equal(t, []string{"keyB", "keyZ"}, keys["bravo"])
}

// TestUserAddRecipient_UnknownUserErrors rejects a user that does not exist.
func TestUserAddRecipient_UnknownUserErrors(t *testing.T) {
	dir := t.TempDir()
	main := writeTwoUserMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.Error(t, cr.UserAddRecipient("ghost", []string{"keyZ"}))
}

// TestUserRmRecipient_RemovesKey drops a single key, leaving the rest in order.
func TestUserRmRecipient_RemovesKey(t *testing.T) {
	dir := t.TempDir()
	main := writeMultiKeyMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserRmRecipient("axolotl", []string{"keyA2"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"keyA1", "keyA3"}, keysByUser(t, main)["axolotl"])
}

// TestUserRmRecipient_RemovesMultiple drops several keys at once.
func TestUserRmRecipient_RemovesMultiple(t *testing.T) {
	dir := t.TempDir()
	main := writeMultiKeyMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserRmRecipient("axolotl", []string{"keyA1", "keyA3"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"keyA2"}, keysByUser(t, main)["axolotl"])
}

// TestUserRmRecipient_TargetsNamedUser removes only from the named user; the
// other user's keys are untouched.
func TestUserRmRecipient_TargetsNamedUser(t *testing.T) {
	dir := t.TempDir()
	main := writeMultiKeyMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserRmRecipient("axolotl", []string{"keyA1"}))
	require.NoError(t, cr.Save())

	keys := keysByUser(t, main)
	require.Equal(t, []string{"keyA2", "keyA3"}, keys["axolotl"])
	require.Equal(t, []string{"keyB1", "keyB2"}, keys["bravo"], "untargeted user must be unchanged")
}

// TestUserRmRecipient_AbsentKeyIsNoop removing a key the user doesn't have
// leaves the list intact and returns no error.
func TestUserRmRecipient_AbsentKeyIsNoop(t *testing.T) {
	dir := t.TempDir()
	main := writeMultiKeyMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.UserRmRecipient("axolotl", []string{"not-a-key"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"keyA1", "keyA2", "keyA3"}, keysByUser(t, main)["axolotl"])
}

// TestUserRmRecipient_RejectsRemovingLastKeys refuses to leave a user with no
// keys: removing every key returns an error and the key list is left intact.
func TestUserRmRecipient_RejectsRemovingLastKeys(t *testing.T) {
	dir := t.TempDir()
	main := writeMultiKeyMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)

	err = cr.UserRmRecipient("axolotl", []string{"keyA1", "keyA2", "keyA3"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one key")

	// The rejected removal left the keys untouched; they survive a round trip.
	require.NoError(t, cr.Save())
	require.Equal(t, []string{"keyA1", "keyA2", "keyA3"}, keysByUser(t, main)["axolotl"])
}

// TestUserRmRecipient_UnknownUserErrors rejects a user that does not exist.
func TestUserRmRecipient_UnknownUserErrors(t *testing.T) {
	dir := t.TempDir()
	main := writeMultiKeyMain(t, dir)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.Error(t, cr.UserRmRecipient("ghost", []string{"keyA1"}))
}
