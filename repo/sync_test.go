package repo

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The decision table behind every state `sesam status` shows and every choice
// reveal, seal and the hooks make. The facts are gathered elsewhere; this pins
// down what they mean, in precedence order.
func TestClassify(t *testing.T) {
	tests := []struct {
		name  string
		facts syncFacts
		want  SecretState
	}{
		{"no access wins over everything", syncFacts{plaintext: true, object: true, matchesObject: true}, SecretStateUserHasNoAccess},
		{"no plaintext", syncFacts{access: true, object: true}, SecretStateNoRevealedPath},
		{"no object yet", syncFacts{access: true, plaintext: true}, SecretStateNoSealedPath},
		{"plaintext is the object's", syncFacts{access: true, plaintext: true, object: true, matchesObject: true}, SecretStateInSync},
		{"plaintext matches, recipients moved: needs a reseal, not an edit", syncFacts{access: true, plaintext: true, object: true, matchesObject: true, recipientsChanged: true}, SecretStateRecipientsChanged},
		{"matching the worktree object beats an older match", syncFacts{access: true, plaintext: true, object: true, matchesObject: true, matchesOlder: true}, SecretStateInSync},
		{"plaintext is an earlier version and object is not older: stale", syncFacts{access: true, plaintext: true, object: true, matchesOlder: true, objectNotOlder: true}, SecretStateStale},
		{"older match written after object: modified", syncFacts{access: true, plaintext: true, object: true, matchesOlder: true}, SecretStateNotInSync},
		{"stale even when the operation moved the object", syncFacts{access: true, plaintext: true, object: true, matchesOlder: true, objectNotOlder: true, objectMoved: true}, SecretStateStale},
		{"matches nothing, object untouched: modified", syncFacts{access: true, plaintext: true, object: true}, SecretStateNotInSync},
		{"matches nothing, object moved: diverged", syncFacts{access: true, plaintext: true, object: true, objectMoved: true}, SecretStateDiverged},
		{"a conflict being resolved is modified, not diverged", syncFacts{access: true, plaintext: true, object: true, objectMoved: true, unmerged: true}, SecretStateNotInSync},
		{"a resolution that equals an older version is still a resolution", syncFacts{access: true, plaintext: true, object: true, matchesOlder: true, unmerged: true}, SecretStateNotInSync},
		{"unmerged without a moved object is plain modified", syncFacts{access: true, plaintext: true, object: true, unmerged: true}, SecretStateNotInSync},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, classify(tc.facts))
		})
	}
}

func TestSyncStatesPaths(t *testing.T) {
	states := SyncStates{
		"b": SecretStateStale,
		"a": SecretStateStale,
		"c": SecretStateNotInSync,
		"d": SecretStateInSync,
	}

	require.Equal(t, []string{"a", "b"}, states.Paths(SecretStateStale))
	require.Equal(t, []string{"a", "b", "c"}, states.Paths(SecretStateStale, SecretStateNotInSync))
	require.Empty(t, states.Paths(SecretStateDiverged))
	require.Nil(t, SyncStates{}.Paths(SecretStateInSync))
}

func TestSyncStatesOlderMatchUsesMtime(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)
	const secret = "secrets/api-token"

	writeRepoFile(t, dir, secret, "old")
	require.NoError(t, r.Update(func(s *Stage) error {
		if err := s.SecretAdd(t.Context(), []string{secret}, []string{"admin"}, false, false); err != nil {
			return err
		}
		_, err := s.Seal(t.Context(), SealOpts{})
		return err
	}))
	gitCommitAll(t, dir, "add secret")

	writeRepoFile(t, dir, secret, "new")
	require.NoError(t, r.Update(func(s *Stage) error {
		_, err := s.Seal(t.Context(), SealOpts{})
		return err
	}))

	plaintext := filepath.Join(dir, secret)
	object := filepath.Join(dir, r.secret.SealedPath(secret))
	objectTime := time.Unix(1_700_000_000, 0)
	require.NoError(t, os.Chtimes(object, objectTime, objectTime))
	writeRepoFile(t, dir, secret, "old")

	require.NoError(t, os.Chtimes(plaintext, objectTime.Add(time.Minute), objectTime.Add(time.Minute)))
	states, err := r.SyncStates(t.Context(), SyncOpts{})
	require.NoError(t, err)
	require.Equal(t, SecretStateNotInSync, states[secret])

	require.NoError(t, os.Chtimes(plaintext, objectTime, objectTime))
	states, err = r.SyncStates(t.Context(), SyncOpts{})
	require.NoError(t, err)
	require.Equal(t, SecretStateStale, states[secret])

	require.NoError(t, os.Chtimes(plaintext, objectTime.Add(-time.Minute), objectTime.Add(-time.Minute)))
	states, err = r.SyncStates(t.Context(), SyncOpts{})
	require.NoError(t, err)
	require.Equal(t, SecretStateStale, states[secret])
}
