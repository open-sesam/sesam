package core

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// HTTP is intentionally not exercised here: VerifyForgeIds delegates to
// ParseAndResolveRecipients, which dispatches on the KeySource prefix. The
// file:// branch and the https:// / forge branches are equivalent from
// VerifyForgeIds' point of view — both yield a non-manual KeySource that is
// re-fetched on each call. Using file:// keeps the test hermetic; the
// HTTP-specific resolveLink code path is covered by recipient_test.go.

// writeForgeFile writes a single age public-key string to dir/name and returns
// the matching relative file:// KeySource (resolved through the fixture root).
// Overwriting the file between calls simulates the upstream key set changing.
func writeForgeFile(t *testing.T, dir, name, key string) KeySource {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(key), 0o600))
	return KeySource("file://" + name)
}

// recipientFromKey parses an age public-key string and tags it with src so the
// producer in VerifyForgeIds dispatches a re-fetch job for it.
func recipientFromKey(t *testing.T, key string, src KeySource) *Recipient {
	t.Helper()
	r, err := ParseRecipient(key, NewNonInteractivePluginUI())
	require.NoError(t, err)
	r.Source = src
	return r
}

// forgeFixture wires up a VerifiedState and a Keyring that agree on user
// membership, mirroring what LoadAuditLog + Verify would produce in real use.
type forgeFixture struct {
	Dir   string
	Root  *os.Root
	State *VerifiedState
	Kr    *MemoryKeyring
}

func newForgeFixture(t *testing.T) *forgeFixture {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })
	return &forgeFixture{
		Dir:   dir,
		Root:  root,
		State: &VerifiedState{},
		Kr:    EmptyKeyring(),
	}
}

func (f *forgeFixture) addUser(t *testing.T, name string, recps ...*Recipient) {
	t.Helper()
	f.State.Users = append(f.State.Users, VerifiedUser{Name: name, Recps: recps})
	for _, r := range recps {
		f.Kr.AddRecipient(name, r)
	}
}

// keyOf returns a freshly generated age public-key string. Convenience over
// constructing a full testUser when we only need the key material.
func keyOf(t *testing.T, name string) string {
	t.Helper()
	return newTestUser(t, name).Recipient.String()
}

func TestVerifyForgeIds_NoForgeUsers(t *testing.T) {
	// Only manual keys: no jobs dispatched, no fetches, empty report.
	f := newForgeFixture(t)
	pu := NewNonInteractivePluginUI()
	r, err := ParseRecipient(keyOf(t, "alice"), pu)
	require.NoError(t, err)
	// ParseRecipient defaults Source to KeySourceManual.
	require.Equal(t, KeySourceManual, r.Source)
	f.addUser(t, "alice", r)

	report := VerifyForgeIds(context.Background(), f.Root, f.State, f.Kr, pu)
	require.NotNil(t, report)
	require.Empty(t, report.Added)
	require.Empty(t, report.Deleted)
	require.Empty(t, report.Errored)
}

func TestVerifyForgeIds_EmptyState(t *testing.T) {
	// Truly nothing to verify.
	f := newForgeFixture(t)
	report := VerifyForgeIds(context.Background(), f.Root, f.State, f.Kr, NewNonInteractivePluginUI())
	require.NotNil(t, report)
	require.Empty(t, report.Added)
	require.Empty(t, report.Deleted)
	require.Empty(t, report.Errored)
}

func TestVerifyForgeIds_Stable(t *testing.T) {
	// Forge content matches keyring exactly: no diff.
	f := newForgeFixture(t)
	aliceKey := keyOf(t, "alice")
	src := writeForgeFile(t, f.Dir, "alice.pub", aliceKey)
	f.addUser(t, "alice", recipientFromKey(t, aliceKey, src))

	report := VerifyForgeIds(context.Background(), f.Root, f.State, f.Kr, NewNonInteractivePluginUI())
	require.Empty(t, report.Added)
	require.Empty(t, report.Deleted)
	require.Empty(t, report.Errored)
}

func TestVerifyForgeIds_KeySwap(t *testing.T) {
	// Forge rotated: keyring has k1, source now returns k2. Both Added and
	// Deleted are populated, with PubKey pointers matching the swapped keys.
	f := newForgeFixture(t)
	oldKey := keyOf(t, "alice-old")
	newKey := keyOf(t, "alice-new")
	require.NotEqual(t, oldKey, newKey)

	// Write k2 to the forge file but configure alice with k1@src.
	src := writeForgeFile(t, f.Dir, "alice.pub", newKey)
	f.addUser(t, "alice", recipientFromKey(t, oldKey, src))

	report := VerifyForgeIds(context.Background(), f.Root, f.State, f.Kr, NewNonInteractivePluginUI())
	require.Len(t, report.Added, 1)
	require.Len(t, report.Deleted, 1)
	require.Empty(t, report.Errored)

	require.Equal(t, "alice", report.Added[0].User)
	require.Equal(t, newKey, report.Added[0].PubKey)

	require.Equal(t, "alice", report.Deleted[0].User)
	require.Equal(t, oldKey, report.Deleted[0].PubKey)
}

func TestVerifyForgeIds_DeletedKey(t *testing.T) {
	// alice has two recipients tagged the same source, but the source only
	// returns the first one. The second must be reported as Deleted (and the
	// duplicate-job dedup must hold: without it, the iteration in the Add
	// loop produces a false-positive Added entry — see review history).
	f := newForgeFixture(t)
	keepKey := keyOf(t, "alice-keep")
	dropKey := keyOf(t, "alice-drop")

	src := writeForgeFile(t, f.Dir, "alice.pub", keepKey)
	f.addUser(
		t, "alice",
		recipientFromKey(t, keepKey, src),
		recipientFromKey(t, dropKey, src),
	)

	report := VerifyForgeIds(context.Background(), f.Root, f.State, f.Kr, NewNonInteractivePluginUI())
	require.Empty(t, report.Added,
		"dedup regression: false-positive Added entry caused by duplicate (user,source) jobs")
	require.Empty(t, report.Errored)
	require.Len(t, report.Deleted, 1)
	require.Equal(t, "alice", report.Deleted[0].User)
	require.Equal(t, dropKey, report.Deleted[0].PubKey)
}

func TestVerifyForgeIds_ErroredOnMissingSource(t *testing.T) {
	// Source points at a non-existent file: ParseAndResolveRecipients errors
	// and the user lands in Errored. A failed fetch must NOT be conflated
	// with the key being deleted upstream — the error-clearing loop sweeps
	// errored sources out of currUserMap before the leftover pass.
	f := newForgeFixture(t)
	aliceKey := keyOf(t, "alice")
	missingSrc := KeySource("file://does-not-exist.pub")
	f.addUser(t, "alice", recipientFromKey(t, aliceKey, missingSrc))

	report := VerifyForgeIds(context.Background(), f.Root, f.State, f.Kr, NewNonInteractivePluginUI())
	require.Empty(t, report.Added)
	require.Empty(t, report.Deleted,
		"a fetch failure must not be conflated with the key being deleted upstream")
	require.Len(t, report.Errored, 1)
	require.Equal(t, "alice", report.Errored[0].User)
	require.Equal(t, missingSrc, report.Errored[0].Source)
	require.Error(t, report.Errored[0].Error)
}

func TestVerifyForgeIds_PartialErrorPreservesUnaffectedSources(t *testing.T) {
	// alice has two keys from two different sources. S2 fetch fails; S1
	// succeeds and matches its current recipient. Only S2 should land in
	// Errored — k1 must not appear in Deleted, and k2 must not either (we
	// can't tell whether k2 is still present in S2 or has been removed).
	f := newForgeFixture(t)
	k1 := keyOf(t, "alice-k1")
	k2 := keyOf(t, "alice-k2")
	s1 := writeForgeFile(t, f.Dir, "k1.pub", k1)
	s2 := KeySource("file://k2-missing.pub")
	f.addUser(
		t, "alice",
		recipientFromKey(t, k1, s1),
		recipientFromKey(t, k2, s2),
	)

	report := VerifyForgeIds(context.Background(), f.Root, f.State, f.Kr, NewNonInteractivePluginUI())
	require.Empty(t, report.Added)
	require.Empty(t, report.Deleted)
	require.Len(t, report.Errored, 1)
	require.Equal(t, "alice", report.Errored[0].User)
	require.Equal(t, s2, report.Errored[0].Source)
}

func TestVerifyForgeIds_ManualKeyNeverReportedAsDeleted(t *testing.T) {
	// alice has one manual key and one forge key that disappears from its
	// source. The manual key must not appear in Deleted (the leftover sweep
	// has to filter KeySourceManual out — without that filter, every manual
	// key would leak into the report).
	f := newForgeFixture(t)
	manualKey := keyOf(t, "alice-manual")
	forgeKey := keyOf(t, "alice-forge")

	manual, err := ParseRecipient(manualKey, NewNonInteractivePluginUI())
	require.NoError(t, err)
	require.Equal(t, KeySourceManual, manual.Source)

	// Source file deliberately holds an unrelated key, so the forge key looks deleted.
	otherKey := keyOf(t, "someone-else")
	src := writeForgeFile(t, f.Dir, "alice.pub", otherKey)
	f.addUser(t, "alice", manual, recipientFromKey(t, forgeKey, src))

	report := VerifyForgeIds(context.Background(), f.Root, f.State, f.Kr, NewNonInteractivePluginUI())

	for _, entry := range report.Deleted {
		require.NotEqual(t, manualKey, entry.PubKey,
			"manual key must never appear in Deleted")
	}

	// Sanity: forge key is reported deleted, otherKey is reported added.
	require.Len(t, report.Deleted, 1)
	require.Equal(t, forgeKey, report.Deleted[0].PubKey)
	require.Len(t, report.Added, 1)
	require.Equal(t, otherKey, report.Added[0].PubKey)
}

func TestVerifyForgeIds_KeyringNotMutated(t *testing.T) {
	// Regression test for the slices.Delete-on-shared-backing-array bug:
	// VerifyForgeIds used to walk the keyring's own slices in-place, which
	// silently zeroed tail entries of MemoryKeyring.recipients. After the
	// slices.Clone fix, the keyring must be byte-identical after a call,
	// including the case that did mutate (a user whose forge dropped a key).
	f := newForgeFixture(t)
	keepKey := keyOf(t, "alice-keep")
	dropKey := keyOf(t, "alice-drop")
	src := writeForgeFile(t, f.Dir, "alice.pub", keepKey)
	r1 := recipientFromKey(t, keepKey, src)
	r2 := recipientFromKey(t, dropKey, src)
	f.addUser(t, "alice", r1, r2)

	// Snapshot identity of each recipient pointer in slot order so we can
	// detect both reordering and nil-ing of tail entries.
	before := slices.Clone(f.Kr.ListUsers()["alice"])
	require.Equal(t, Recipients{r1, r2}, before)

	report := VerifyForgeIds(context.Background(), f.Root, f.State, f.Kr, NewNonInteractivePluginUI())
	require.Len(t, report.Deleted, 1, "fixture must actually exercise the previously-mutating code path")

	after := f.Kr.ListUsers()["alice"]
	require.Equal(t, before, after,
		"keyring slice must be untouched (no reorder, no nil tail) after VerifyForgeIds")
	for i, r := range after {
		require.NotNil(t, r, "recipient at index %d went nil — slices.Delete leaked through", i)
	}
}

func TestVerifyForgeIds_MultipleUsersSorted(t *testing.T) {
	// Cover concurrent fan-out across users and assert the sort produced by
	// the final SortStableFunc-by-User call (within-user ordering is not
	// guaranteed today; we have one entry per user here to avoid relying on
	// it).
	f := newForgeFixture(t)

	// alice: stable.
	aliceKey := keyOf(t, "alice")
	aliceSrc := writeForgeFile(t, f.Dir, "alice.pub", aliceKey)
	f.addUser(t, "alice", recipientFromKey(t, aliceKey, aliceSrc))

	// bob: key swapped upstream.
	bobOld := keyOf(t, "bob-old")
	bobNew := keyOf(t, "bob-new")
	bobSrc := writeForgeFile(t, f.Dir, "bob.pub", bobNew)
	f.addUser(t, "bob", recipientFromKey(t, bobOld, bobSrc))

	// charlie: forge unreachable.
	charlieKey := keyOf(t, "charlie")
	charlieSrc := KeySource("file://charlie-missing.pub")
	f.addUser(t, "charlie", recipientFromKey(t, charlieKey, charlieSrc))

	report := VerifyForgeIds(context.Background(), f.Root, f.State, f.Kr, NewNonInteractivePluginUI())

	require.Len(t, report.Added, 1)
	require.Equal(t, "bob", report.Added[0].User)
	require.Equal(t, bobNew, report.Added[0].PubKey)

	require.Len(t, report.Deleted, 1, "charlie's errored fetch must not leak as Deleted")
	require.Equal(t, "bob", report.Deleted[0].User)
	require.Equal(t, bobOld, report.Deleted[0].PubKey)

	require.Len(t, report.Errored, 1)
	require.Equal(t, "charlie", report.Errored[0].User)
	require.Equal(t, charlieSrc, report.Errored[0].Source)

	// Sort assertion: with multiple users, Added/Deleted/Errored are ordered
	// by User. This is more interesting once any of those slices has >1 entry
	// per call, but checking it now pins the contract.
	require.True(t, slices.IsSortedFunc(report.Added, func(a, b ForgeReportEntry) int {
		return cmpStr(a.User, b.User)
	}))
	require.True(t, slices.IsSortedFunc(report.Deleted, func(a, b ForgeReportEntry) int {
		return cmpStr(a.User, b.User)
	}))
	require.True(t, slices.IsSortedFunc(report.Errored, func(a, b ForgeReportError) int {
		return cmpStr(a.User, b.User)
	}))
}

func TestVerifyForgeIds_AddedAcrossMultipleUsers(t *testing.T) {
	// Two distinct users each with one Added entry: exercises the worker
	// fan-out and the sort-by-user output ordering.
	f := newForgeFixture(t)

	aliceOld := keyOf(t, "alice-old")
	aliceNew := keyOf(t, "alice-new")
	aliceSrc := writeForgeFile(t, f.Dir, "alice.pub", aliceNew)
	f.addUser(t, "alice", recipientFromKey(t, aliceOld, aliceSrc))

	bobOld := keyOf(t, "bob-old")
	bobNew := keyOf(t, "bob-new")
	bobSrc := writeForgeFile(t, f.Dir, "bob.pub", bobNew)
	f.addUser(t, "bob", recipientFromKey(t, bobOld, bobSrc))

	report := VerifyForgeIds(context.Background(), f.Root, f.State, f.Kr, NewNonInteractivePluginUI())
	require.Len(t, report.Added, 2)
	require.Equal(t, "alice", report.Added[0].User)
	require.Equal(t, "bob", report.Added[1].User)
	require.Len(t, report.Deleted, 2)
	require.Equal(t, "alice", report.Deleted[0].User)
	require.Equal(t, "bob", report.Deleted[1].User)
	require.Empty(t, report.Errored)
}

// cmpStr is the standard string comparator; pulled out so test sort assertions
// read as "sorted by user" rather than as inline strings.Compare clutter.
func cmpStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
