package repo

import (
	"testing"

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
		{"plaintext is an earlier version: stale", syncFacts{access: true, plaintext: true, object: true, matchesOlder: true}, SecretStateStale},
		{"stale even when the operation moved the object", syncFacts{access: true, plaintext: true, object: true, matchesOlder: true, objectMoved: true}, SecretStateStale},
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
