package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// verifyState builds a minimal VerifiedState with the given audit log and keyring,
// then runs the inner verify function (skipping git checks).
func verifyState(t *testing.T, al *AuditLog, kr Keyring) *VerifiedState {
	t.Helper()
	state := &VerifiedState{auditLog: al, keyring: kr}
	require.NoError(t, verify(state))
	return state
}

func verifyStateFail(t *testing.T, al *AuditLog, kr Keyring) error {
	t.Helper()
	state := &VerifiedState{auditLog: al, keyring: kr}
	return verify(state)
}

// --- verifyInit tests ---

func TestVerifyInitBasic(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	state := verifyState(t, al, EmptyKeyring())
	require.Len(t, state.Users, 1)
	require.Equal(t, "admin", state.Users[0].Name)
	require.True(t, state.Users[0].IsAdmin())
}

func TestVerifyInitNegative(t *testing.T) {
	t.Run("wrong seq_id", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)
		al.Entries[0].SeqID = 5
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("hash mismatch", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)
		al.InitHash = "bogus-hash"
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("admin not in admin group", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		tell := admin.DetailUserTell([]string{"dev"})
		al, err := InitAuditLog(testRoot(t, sesamDir), admin.Signer, Recipients{admin.Recipient}, tell)
		require.NoError(t, err)
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("changedBy mismatch", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)
		al.Entries[0].ChangedBy = "eve"
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})
}

// --- verifyUserTell tests ---

func TestVerifyUserTellBasic(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)

	state := verifyState(t, al, EmptyKeyring())
	require.Len(t, state.Users, 2)
	bobUser, exists := state.UserExists("bob")
	require.True(t, exists)
	require.False(t, bobUser.IsAdmin())
}

func TestVerifyUserTellNegative(t *testing.T) {
	t.Run("non-admin signer", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
		}), nil)

		carol := newTestUser(t, "carol")
		al.AddEntry(bob.Signer, newAuditEntry("bob", &DetailUserTell{
			User: "carol", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: carol.Recipient.String(), Source: KeySourceManual}}, SignPubKey: carol.SignPubKey,
		}), nil)

		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("self add", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "admin", Groups: []string{"admin"},
			PubKeys: []UserPubKey{{Key: admin.Recipient.String(), Source: KeySourceManual}}, SignPubKey: admin.SignPubKey,
		}), nil)

		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("duplicate user", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		tell := &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
		}
		al.AddEntry(admin.Signer, newAuditEntry("admin", tell), nil)
		al.AddEntry(admin.Signer, newAuditEntry("admin", tell), nil)

		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})
}

// --- verifyUserKill tests ---

// TestVerifyForbiddenSecretPath asserts that the verification layer - the trust
// boundary for a pushed repo - rejects secret paths that a reveal could use to
// overwrite sesam's own state or git's (.git/, .sesam/, sesam.yml, ...). The
// CLI guards these too, but a hand-crafted log must not slip past verify.
func TestVerifyForbiddenSecretPath(t *testing.T) {
	forbidden := []string{
		".git/config",
		".git/hooks/pre-commit",
		"sesam.yml",
		"nested/.sesam/objects/x",
		".gitignore",
	}

	// Creation is blocked: a non-admin in a shared group cannot FeedEntry a
	// forbidden secret.add, even though they are authorized for the group.
	t.Run("feed entry rejected", func(t *testing.T) {
		for _, path := range forbidden {
			sesamDir := testRepo(t)
			admin := newTestUser(t, "admin")
			al := initAuditLog(t, sesamDir, admin)
			state := verifyState(t, al, EmptyKeyring())

			eve := newTestUser(t, "eve")
			tell := eve.DetailUserTell([]string{"dev"})
			require.NoError(t, state.FeedEntry(admin.Signer, newAuditEntry("admin", &tell)))

			err := state.FeedEntry(eve.Signer, newAuditEntry("eve", &DetailSecretAdd{
				RevealedPath: path,
				AccessGroups: []string{"dev"},
			}))
			require.Error(t, err, "verifier must reject secret.add for %q", path)
		}
	})

	// Detection: a log that already carries a forbidden secret.add (appended
	// with verify disabled, mimicking a hand-crafted push) fails on replay.
	t.Run("replay alerts on crafted log", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
			RevealedPath: ".git/config",
			AccessGroups: []string{"admin"},
		}), nil)
		require.NoError(t, err)

		err = verifyStateFail(t, al, EmptyKeyring())
		require.Error(t, err, "verify must alert on a log containing a forbidden secret path")
	})

	// A secret.move onto a forbidden path is rejected the same way.
	t.Run("move onto forbidden path rejected", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)
		state := verifyState(t, al, EmptyKeyring())

		require.NoError(t, state.FeedEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
			RevealedPath: "secrets/token",
			AccessGroups: []string{"admin"},
		})))

		err := state.FeedEntry(admin.Signer, newAuditEntry("admin", &DetailSecretMove{
			OldRevealedPath: "secrets/token",
			NewRevealedPath: ".git/hooks/pre-commit",
		}))
		require.Error(t, err, "verifier must reject secret.move onto a forbidden path")
	})
}

// TestVerifyFeedEntryRollback asserts that a FeedEntry whose verification fails
// part-way through leaves the keyring and state exactly as they were. The
// keyring is shared by pointer with the repo and managers, so a failed replay
// must roll its contents back in place rather than leak partial mutations; the
// state is replayed into a deep copy that is discarded on error.
func TestVerifyFeedEntryRollback(t *testing.T) {
	t.Run("keyring not polluted by partial registerUser", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)
		state := verifyState(t, al, EmptyKeyring())
		kr := state.keyring.(*MemoryKeyring)

		usersBefore := len(state.Users)
		recpsBefore := len(AllRecipients(kr))
		signPubsBefore := len(kr.signPubs)

		// eve has her own signing key but reuses admin's recipient. registerUser
		// sets the signing key first (succeeds) and then fails adding the
		// duplicate recipient - the signing key must not survive.
		eve := newTestUser(t, "eve")
		err := state.FeedEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User:       "eve",
			Groups:     []string{"dev"},
			PubKeys:    []UserPubKey{{Key: admin.Recipient.String(), Source: KeySourceManual}},
			SignPubKey: eve.SignPubKey,
		}))
		require.Error(t, err)

		require.Len(t, state.Users, usersBefore)
		require.Len(t, AllRecipients(kr), recpsBefore)
		require.Len(t, kr.signPubs, signPubsBefore)
		_, hasEve := kr.signPubs["eve"]
		require.False(t, hasEve, "phantom signing key for eve must not survive a failed verify")
	})

	t.Run("in-place state mutation rolled back on later failure", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)
		state := verifyState(t, al, EmptyKeyring())

		bob := newTestUser(t, "bob")
		require.NoError(t, state.FeedEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User:       "bob",
			Groups:     []string{"dev"},
			PubKeys:    []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}},
			SignPubKey: bob.SignPubKey,
		})))

		bobUser, ok := state.UserExists("bob")
		require.True(t, ok)
		require.Equal(t, []string{"dev"}, bobUser.Groups)

		// change_groups mutates bob.Groups in place before the signature check.
		// An impostor signer reusing the "admin" name passes the logical checks
		// but fails the signature check *after* the mutation; bob's groups must
		// be left untouched because verify replays into a deep copy.
		impostor := newTestUser(t, "admin")
		err := state.FeedEntry(impostor.Signer, newAuditEntry("admin", &DetailUserChangeGroups{
			User:      "bob",
			NewGroups: []string{"ops"},
		}))
		require.Error(t, err)

		bobUser, ok = state.UserExists("bob")
		require.True(t, ok)
		require.Equal(t, []string{"dev"}, bobUser.Groups, "bob's groups must survive a failed verify unchanged")
	})
}

func TestVerifyUserKillBasic(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserKill{User: "bob"}), nil)

	state := verifyState(t, al, EmptyKeyring())
	_, exists := state.UserExists("bob")
	require.False(t, exists)
	require.Len(t, state.Users, 1)
}

func TestVerifyUserKillNegative(t *testing.T) {
	t.Run("last admin", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserKill{User: "admin"}), nil)
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("non-existent user", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserKill{User: "ghost"}), nil)
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("non-admin signer", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
		}), nil)

		al.AddEntry(bob.Signer, newAuditEntry("bob", &DetailUserKill{User: "admin"}), nil)
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})
}

func TestVerifyUserKillSecondAdmin(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"admin"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserKill{User: "bob"}), nil)

	state := verifyState(t, al, EmptyKeyring())
	_, exists := state.UserExists("bob")
	require.False(t, exists)
}

// --- verifySecretChange tests ---

func TestVerifySecretChangeBasic(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/db", AccessGroups: []string{"dev"},
	}), nil)

	state := verifyState(t, al, EmptyKeyring())
	s, exists := state.SecretExists("secrets/db")
	require.True(t, exists)
	require.Equal(t, "secrets/db", s.RevealedPath)
}

// Empty groups is not an error: it means the secret is accessible to admins
// only (admin is always implicitly added).
func TestVerifySecretChangeEmptyGroupsMeansAdminOnly(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/db", AccessGroups: []string{},
	}), nil)

	state := verifyState(t, al, EmptyKeyring())
	s, exists := state.SecretExists("secrets/db")
	require.True(t, exists)
	require.Equal(t, []string{"admin"}, s.AccessGroups,
		"empty groups must resolve to admin-only access")
}

func TestVerifySecretChangeNegative(t *testing.T) {
	t.Run("no access to existing secret", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
		}), nil)

		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
			RevealedPath: "secrets/db", AccessGroups: []string{"ops"},
		}), nil)

		// Bob (dev) tries to change ops-only secret.
		al.AddEntry(bob.Signer, newAuditEntry("bob", &DetailSecretChangeAccess{
			RevealedPath: "secrets/db", AccessGroups: []string{"dev"},
		}), nil)

		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})
}

func TestVerifySecretChangeUpdate(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/db", AccessGroups: []string{"dev"},
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChangeAccess{
		RevealedPath: "secrets/db", AccessGroups: []string{"ops"},
	}), nil)

	state := verifyState(t, al, EmptyKeyring())
	s, _ := state.SecretExists("secrets/db")
	require.Contains(t, s.AccessGroups, "ops")
}

// Regression: the verify layer must reject any RevealedPath that contains
// path-traversal components. Previously only the high-level API validated
// the path, so a hand-crafted entry could seed state.Secrets with
// "../../.ssh/authorized_keys", causing Reveal to write outside the repo.
func TestVerifySecretChangeRejectsPathTraversal(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "../../.ssh/authorized_keys",
		AccessGroups: []string{"admin"},
	}), nil)

	err := verifyStateFail(t, al, EmptyKeyring())
	require.Error(t, err)
	require.Contains(t, err.Error(), "..")
}

// Regression: creating a new secret must require the creator to be a member
// of at least one of the proposed groups. Previously the new-secret branch
// had no authorization check, letting any user seed state.Secrets with
// arbitrary AccessGroups (and paths).
func TestVerifySecretChangeNewSecretRequiresAccess(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)

	// Bob (dev) tries to register a brand-new secret restricted to "ops".
	al.AddEntry(bob.Signer, newAuditEntry("bob", &DetailSecretAdd{
		RevealedPath: "secrets/ops-db", AccessGroups: []string{"ops"},
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

// --- verifySecretRemove tests ---

func TestVerifySecretRemoveBasic(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/db", AccessGroups: []string{"dev"},
	}), nil)
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretRemove{
		RevealedPath: "secrets/db",
	}), nil)

	state := verifyState(t, al, EmptyKeyring())
	_, exists := state.SecretExists("secrets/db")
	require.False(t, exists)
}

func TestVerifySecretRemoveNegative(t *testing.T) {
	t.Run("non-existent", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretRemove{RevealedPath: "ghost"}), nil)
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("no access", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
		}), nil)

		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
			RevealedPath: "secrets/db", AccessGroups: []string{"ops"},
		}), nil)

		al.AddEntry(bob.Signer, newAuditEntry("bob", &DetailSecretRemove{RevealedPath: "secrets/db"}), nil)
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})
}

// --- verifySeal tests ---

func TestVerifySealResetsRequirement(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{
		RootHash: "some-hash", FilesSealed: 1,
	}), nil)

	state := verifyState(t, al, EmptyKeyring())
	require.Equal(t, uint64(0), state.SealRequiredSeqID)
	require.Equal(t, "some-hash", state.LastSealRootHash)
}

// --- Signature verification tests ---

func TestVerifySignatureNegative(t *testing.T) {
	t.Run("wrong signer", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		// Entry says admin but bob signs it.
		al.AddEntry(bob.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
		}), nil)

		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("tampered signature", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)
		al.Entries[0].Signature = "bogus"
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	// A corrupted signature makes the batch path reject the whole log; verify()
	// must then fall back to serial verification and surface the precise
	// per-entry error, not leak the internal errBatchSignatureRejected sentinel.
	t.Run("batch rejection falls back to precise error", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
		}), nil)

		al.Entries[1].Signature = "bogus"

		err := verifyStateFail(t, al, EmptyKeyring())
		require.Error(t, err)
		require.NotErrorIs(t, err, errBatchSignatureRejected)
		require.Contains(t, err.Error(), "failed to verify signature on entry")
	})
}

// --- Chain integrity tests ---

func TestVerifyChainIntegrity(t *testing.T) {
	t.Run("tampered previous hash", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
		}), nil)

		al.Entries[1].PreviousHash = "broken"
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("swapped entries", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
		}), nil)

		carol := newTestUser(t, "carol")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "carol", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: carol.Recipient.String(), Source: KeySourceManual}}, SignPubKey: carol.SignPubKey,
		}), nil)

		// Swap entries 1 and 2 - should break chain.
		al.Entries[1], al.Entries[2] = al.Entries[2], al.Entries[1]
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("deleted middle entry", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
		}), nil)

		carol := newTestUser(t, "carol")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "carol", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: carol.Recipient.String(), Source: KeySourceManual}}, SignPubKey: carol.SignPubKey,
		}), nil)

		// Remove middle entry - chain breaks.
		al.Entries = append(al.Entries[:1], al.Entries[2:]...)
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("tampered entry content", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
		}), nil)

		// Tamper the init entry's detail (changes its hash, breaking chain for entry 2).
		al.Entries[0].Detail = []byte(`{"init_uuid":"tampered","admin":{}}`)
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})
}

// --- Unknown operation ---

func TestVerifyUnknownOperation(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{RootHash: "x", FilesSealed: 0}), nil)
	al.Entries[len(al.Entries)-1].Operation = "unknown.op"

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

// --- VerifiedState helper tests ---

func TestIsAdmin(t *testing.T) {
	adminUser := VerifiedUser{Name: "a", Groups: []string{"admin", "dev"}}
	devUser := VerifiedUser{Name: "b", Groups: []string{"dev"}}
	require.True(t, adminUser.IsAdmin())
	require.False(t, devUser.IsAdmin())
}

func TestUserExists(t *testing.T) {
	state := &VerifiedState{
		Users: []VerifiedUser{{Name: "alice"}, {Name: "bob"}},
	}

	u, ok := state.UserExists("alice")
	require.True(t, ok)
	require.Equal(t, "alice", u.Name)

	_, ok = state.UserExists("eve")
	require.False(t, ok)
}

func TestSecretExists(t *testing.T) {
	state := &VerifiedState{
		Secrets: []VerifiedSecret{{RevealedPath: "secrets/a"}},
	}

	s, ok := state.SecretExists("secrets/a")
	require.True(t, ok)
	require.Equal(t, "secrets/a", s.RevealedPath)

	_, ok = state.SecretExists("secrets/b")
	require.False(t, ok)
}

func TestUserHasAccess(t *testing.T) {
	state := &VerifiedState{
		Users: []VerifiedUser{
			{Name: "alice", Groups: []string{"admin"}},
			{Name: "bob", Groups: []string{"dev"}},
		},
	}

	require.True(t, state.UserHasAccess("alice", []string{"ops"}), "admin has implicit access")
	require.False(t, state.UserHasAccess("bob", []string{"ops"}), "bob not in ops")
	require.True(t, state.UserHasAccess("bob", []string{"dev"}), "bob in dev")
}

func TestUsersForSecret(t *testing.T) {
	state := &VerifiedState{
		Users: []VerifiedUser{
			{Name: "alice", Groups: []string{"admin"}},
			{Name: "bob", Groups: []string{"dev"}},
			{Name: "carol", Groups: []string{"ops"}},
		},
		Secrets: []VerifiedSecret{
			{RevealedPath: "secrets/db", AccessGroups: []string{"dev"}},
		},
	}

	users := state.UsersForSecret("secrets/db")
	require.Len(t, users, 2) // alice (admin) + bob (dev)
	require.Nil(t, state.UsersForSecret("secrets/ghost"))
}

func TestUserForGroups(t *testing.T) {
	state := &VerifiedState{
		Users: []VerifiedUser{
			{Name: "alice", Groups: []string{"admin"}},
			{Name: "bob", Groups: []string{"dev"}},
			{Name: "carol", Groups: []string{"ops", "dev"}},
		},
	}

	users := state.UserForGroups([]string{"dev"})
	require.Len(t, users, 3) // admin implicit + bob + carol
}

func TestRequireAdmin(t *testing.T) {
	state := &VerifiedState{
		Users: []VerifiedUser{
			{Name: "alice", Groups: []string{"admin"}},
			{Name: "bob", Groups: []string{"dev"}},
		},
	}

	entry := &AuditEntrySigned{AuditEntry: AuditEntry{ChangedBy: "alice", SeqID: 1}}
	u, err := state.RequireAdmin(entry)
	require.NoError(t, err)
	require.Equal(t, "alice", u.Name)

	entry.ChangedBy = "bob"
	_, err = state.RequireAdmin(entry)
	require.Error(t, err, "bob is not admin")

	entry.ChangedBy = "ghost"
	_, err = state.RequireAdmin(entry)
	require.Error(t, err, "ghost does not exist")
}

// --- Update (incremental verify) tests ---

func TestUpdate(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	state := verifyState(t, al, EmptyKeyring())
	require.Equal(t, uint64(1), state.VerifiedUntil)

	bob := newTestUser(t, "bob")
	require.NoError(t, state.FeedEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	})))
	require.Equal(t, uint64(2), state.VerifiedUntil)
	_, exists := state.UserExists("bob")
	require.True(t, exists)
}

// --- Exported Verify (with git) ---

func TestVerifyExportedWithGitRepo(t *testing.T) {
	sesamDir, repo := testGitRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	gitCommitAll(t, repo, "init")

	state, err := Verify(al, EmptyKeyring(), nil)
	require.NoError(t, err)
	require.Len(t, state.Users, 1)
}

func TestVerifyExportedRootHashMatch(t *testing.T) {
	sesamDir, repo := testGitRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/test", AccessGroups: []string{"admin"},
	}), nil)

	writeSecret(t, sesamDir, "secrets/test", "content")
	kr2 := testKeyring(t, admin)
	sm := &SecretManager{
		SesamDir: sesamDir, root: testRoot(t, sesamDir), Identities: Identities{admin.Identity},
		Signer: admin.Signer, Keyring: kr2,
	}
	recps := kr2.Recipients([]string{"admin"})

	sig, err := sealSecret(sm, "secrets/test", recps, sm.cryptPath("secrets/test"), "admin")
	require.NoError(t, err)

	rootHash := buildRootHash([]*secretFooter{sig})
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{
		RootHash: rootHash, FilesSealed: 1,
	}), nil)

	gitCommitAll(t, repo, "full setup")

	state, err := Verify(al, EmptyKeyring(), nil)
	require.NoError(t, err)
	require.Equal(t, rootHash, state.LastSealRootHash)
}

func TestVerifyExportedRootHashMismatch(t *testing.T) {
	sesamDir, repo := testGitRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{
		RootHash: "wrong-hash", FilesSealed: 0,
	}), nil)

	gitCommitAll(t, repo, "init")

	_, err := Verify(al, EmptyKeyring(), nil)
	require.Error(t, err, "should detect root hash mismatch")
}

// --- End-to-end ---

func TestEndToEndStoreLoadVerify(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/db", AccessGroups: []string{"dev"},
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{
		RootHash: "test-root-hash", FilesSealed: 1,
	}), nil)

	loaded, err := LoadAuditLog(testRoot(t, sesamDir), Identities{admin.Identity})
	require.NoError(t, err)

	state := verifyState(t, loaded, EmptyKeyring())
	require.Len(t, state.Users, 2)
	require.Len(t, state.Secrets, 1)
	require.Equal(t, "test-root-hash", state.LastSealRootHash)
}

func TestFullLifecycle(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)

	carol := newTestUser(t, "carol")
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "carol", Groups: []string{"ops"},
		PubKeys: []UserPubKey{{Key: carol.Recipient.String(), Source: KeySourceManual}}, SignPubKey: carol.SignPubKey,
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/db_pass", AccessGroups: []string{"dev"},
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/api_key", AccessGroups: []string{"ops"},
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{RootHash: "hash1", FilesSealed: 2}), nil)
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserKill{User: "bob"}), nil)
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretRemove{RevealedPath: "secrets/db_pass"}), nil)
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{RootHash: "hash2", FilesSealed: 1}), nil)

	state := verifyState(t, al, EmptyKeyring())
	require.Len(t, state.Users, 2) // admin + carol
	_, exists := state.UserExists("bob")
	require.False(t, exists)
	require.Len(t, state.Secrets, 1) // api_key only
	_, exists = state.SecretExists("secrets/api_key")
	require.True(t, exists)
	require.Equal(t, "hash2", state.LastSealRootHash)
	require.Equal(t, uint64(0), state.SealRequiredSeqID)
}

// tellUser appends a user.tell entry authored by admin and returns the user.
func tellUser(t *testing.T, al *AuditLog, admin, user *testUser, groups []string) {
	t.Helper()
	tell := user.DetailUserTell(groups)
	_, err := al.AddEntry(admin.Signer, newAuditEntry(admin.Name, &tell), nil)
	require.NoError(t, err)
}

// --- verifyUserRename tests ---

func TestVerifyUserRenameBasic(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	tellUser(t, al, admin, bob, []string{"dev"})

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserRename{
		OldName: "bob", NewName: "bobby",
	}), nil)

	state := verifyState(t, al, EmptyKeyring())

	_, exists := state.UserExists("bob")
	require.False(t, exists, "old name must be gone")

	renamed, exists := state.UserExists("bobby")
	require.True(t, exists, "new name must exist")
	require.Equal(t, []string{"dev"}, renamed.Groups, "groups must be preserved")
}

// Regression: rename must move the user's keys in the keyring too. Otherwise
// the renamed user's *subsequent* entries fail signature verification - the
// signature still matches the old name while ChangedBy is the new name.
func TestVerifyUserRenameUpdatesKeyring(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	tellUser(t, al, admin, bob, []string{"dev"})

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserRename{
		OldName: "bob", NewName: "bobby",
	}), nil)

	// "bobby" (formerly bob, same signing key) authors a later entry. This
	// only verifies if the keyring learned the new name during the rename.
	al.AddEntry(bob.Signer, newAuditEntry("bobby", &DetailSecretAdd{
		RevealedPath: "secrets/db", AccessGroups: []string{"dev"},
	}), nil)

	require.NoError(t, verifyStateFail(t, al, EmptyKeyring()))
}

func TestVerifyUserRenameRejectsInvalidNewName(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	tellUser(t, al, admin, bob, []string{"dev"})

	// A name with a path separator must be rejected - names become path
	// components (.sesam/signkeys/<user>.age).
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserRename{
		OldName: "bob", NewName: "../evil",
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

func TestVerifyUserRenameRejectsCollision(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	tellUser(t, al, admin, bob, []string{"dev"})

	carol := newTestUser(t, "carol")
	tellUser(t, al, admin, carol, []string{"dev"})

	// Renaming bob onto the existing carol must be rejected.
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserRename{
		OldName: "bob", NewName: "carol",
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

func TestVerifyUserRenameRequiresAdmin(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	tellUser(t, al, admin, bob, []string{"dev"})

	// bob (non-admin) tries to rename himself.
	al.AddEntry(bob.Signer, newAuditEntry("bob", &DetailUserRename{
		OldName: "bob", NewName: "bobby",
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

func TestVerifyUserRenameNonExistent(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserRename{
		OldName: "ghost", NewName: "casper",
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

// --- self-mutation edge cases ---
//
// The dispatch loop checks an entry's signature *before* applying the keyring
// changes for kill and rename. That ordering is what makes self-mutation work:
// the signature is verified against the author's still-current keyring entry,
// and only afterwards is that entry moved (rename) or removed (kill). If the
// keyring were mutated first, the signature would resolve to the new name (or
// to nothing), and the entry would be wrongly rejected.

// An admin renaming *themselves* must succeed: the rename entry is signed under
// the old name, verified against it, and only then is the keyring moved to the
// new name.
func TestVerifyUserRenameSelf(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserRename{
		OldName: "admin", NewName: "superadmin",
	}), nil)

	state := verifyState(t, al, EmptyKeyring())

	_, exists := state.UserExists("admin")
	require.False(t, exists, "old name must be gone")

	renamed, exists := state.UserExists("superadmin")
	require.True(t, exists, "new name must exist")
	require.True(t, renamed.IsAdmin(), "admin status must be preserved")
}

// An admin killing *themselves* must succeed once another admin remains (so the
// last-admin guard does not fire). The kill entry is verified against the
// author's key before that key is removed from the keyring.
func TestVerifyUserKillSelf(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	admin2 := newTestUser(t, "admin2")
	tellUser(t, al, admin, admin2, []string{"admin"})

	// admin2 removes admin2; a second admin remains, so last-admin is not the blocker.
	al.AddEntry(admin2.Signer, newAuditEntry("admin2", &DetailUserKill{
		User: "admin2",
	}), nil)

	state := verifyState(t, al, EmptyKeyring())

	_, exists := state.UserExists("admin2")
	require.False(t, exists, "self-killed user must be gone")

	_, exists = state.UserExists("admin")
	require.True(t, exists, "remaining admin must survive")
}

// --- verifyUserChangeGroups tests ---

func TestVerifyUserChangeGroupsBasic(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	tellUser(t, al, admin, bob, []string{"dev"})

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserChangeGroups{
		User: "bob", NewGroups: []string{"ops", "dev"},
	}), nil)

	state := verifyState(t, al, EmptyKeyring())
	bob2, exists := state.UserExists("bob")
	require.True(t, exists)
	require.ElementsMatch(t, []string{"ops", "dev"}, bob2.Groups)
	// change_groups must not implicitly grant admin (unlike the secret paths).
	require.NotContains(t, bob2.Groups, "admin")
	require.Equal(t, state.VerifiedUntil, state.SealRequiredSeqID,
		"a group change requires a re-seal")
}

// Regression: removing "admin" from the only admin must be rejected, otherwise
// the repo is permanently locked out of every admin-gated operation.
func TestVerifyUserChangeGroupsCannotDemoteLastAdmin(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserChangeGroups{
		User: "admin", NewGroups: []string{"dev"},
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

func TestVerifyUserChangeGroupsAllowsDemoteWithOtherAdmin(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	admin2 := newTestUser(t, "admin2")
	tellUser(t, al, admin, admin2, []string{"admin"})

	// admin2 demotes the original admin; a second admin remains, so it's allowed.
	al.AddEntry(admin2.Signer, newAuditEntry("admin2", &DetailUserChangeGroups{
		User: "admin", NewGroups: []string{"dev"},
	}), nil)

	state := verifyState(t, al, EmptyKeyring())
	demoted, _ := state.UserExists("admin")
	require.NotContains(t, demoted.Groups, "admin")
}

func TestVerifyUserChangeGroupsRequiresAdmin(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	tellUser(t, al, admin, bob, []string{"dev"})
	carol := newTestUser(t, "carol")
	tellUser(t, al, admin, carol, []string{"dev"})

	// bob (non-admin) tries to change carol's groups.
	al.AddEntry(bob.Signer, newAuditEntry("bob", &DetailUserChangeGroups{
		User: "carol", NewGroups: []string{"ops"},
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

func TestVerifyUserChangeGroupsNonExistent(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserChangeGroups{
		User: "ghost", NewGroups: []string{"dev"},
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

// --- verifySecretRename tests ---

func TestVerifySecretRenameBasic(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/db", AccessGroups: []string{"admin"},
	}), nil)
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretMove{
		OldRevealedPath: "secrets/db", NewRevealedPath: "secrets/database",
	}), nil)

	state := verifyState(t, al, EmptyKeyring())
	_, exists := state.SecretExists("secrets/db")
	require.False(t, exists, "old path must be gone")
	renamed, exists := state.SecretExists("secrets/database")
	require.True(t, exists, "new path must exist")
	require.Equal(t, "secrets/database", renamed.RevealedPath)
}

func TestVerifySecretRenameRejectsCollision(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/a", AccessGroups: []string{"admin"},
	}), nil)
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/b", AccessGroups: []string{"admin"},
	}), nil)

	// Renaming a onto the existing b must be rejected.
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretMove{
		OldRevealedPath: "secrets/a", NewRevealedPath: "secrets/b",
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

func TestVerifySecretRenameNonExistent(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretMove{
		OldRevealedPath: "secrets/ghost", NewRevealedPath: "secrets/casper",
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

func TestVerifySecretRenameRejectsPathTraversal(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/db", AccessGroups: []string{"admin"},
	}), nil)
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretMove{
		OldRevealedPath: "secrets/db", NewRevealedPath: "../../.ssh/authorized_keys",
	}), nil)

	err := verifyStateFail(t, al, EmptyKeyring())
	require.Error(t, err)
	require.Contains(t, err.Error(), "..")
}

func TestVerifySecretRenameRequiresAccess(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	tellUser(t, al, admin, bob, []string{"dev"})

	// ops-only secret bob (dev) cannot reach.
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
		RevealedPath: "secrets/ops_db", AccessGroups: []string{"ops"},
	}), nil)

	al.AddEntry(bob.Signer, newAuditEntry("bob", &DetailSecretMove{
		OldRevealedPath: "secrets/ops_db", NewRevealedPath: "secrets/mine",
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

// buildCorpus signs numMsgs messages of msgSize bytes, spread round-robin over
// numSigners keys, and returns the checks plus the signer keys (so tests can
// corrupt individual entries).
func buildCorpus(t testing.TB, numSigners, numMsgs, msgSize int) []SigCheck {
	t.Helper()

	pubs := make([]ed25519.PublicKey, numSigners)
	privs := make([]ed25519.PrivateKey, numSigners)
	for i := range numSigners {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		pubs[i], privs[i] = pub, priv
	}

	checks := make([]SigCheck, numMsgs)
	for i := range numMsgs {
		msg := make([]byte, msgSize)
		_, err := rand.Read(msg)
		require.NoError(t, err)

		signer := i % numSigners
		checks[i] = SigCheck{
			PubKey:    pubs[signer],
			Message:   msg,
			Signature: ed25519.Sign(privs[signer], msg),
		}
	}
	return checks
}

// verifySerial verifies every check one at a time with crypto/ed25519. It is
// the reference the batch path is tested and benchmarked against.
func verifySerial(checks []SigCheck) bool {
	for _, c := range checks {
		if len(c.PubKey) != ed25519.PublicKeySize {
			return false
		}
		if !ed25519.Verify(c.PubKey, c.Message, c.Signature) {
			return false
		}
	}
	return true
}

func TestVerifyBatchMatchesSerial(t *testing.T) {
	tests := []struct {
		name       string
		numSigners int
		numMsgs    int
	}{
		{name: "single signer", numSigners: 1, numMsgs: 64},
		{name: "many signers", numSigners: 8, numMsgs: 200},
		{name: "empty batch", numSigners: 1, numMsgs: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checks := buildCorpus(t, max(tc.numSigners, 1), tc.numMsgs, 256)

			require.True(t, verifySerial(checks), "serial must accept a valid corpus")
			require.True(t, verifyBatch(checks), "batch must accept the same corpus")

			if len(checks) == 0 {
				return
			}

			// A single corrupted signature must be rejected by both paths.
			bad := make([]SigCheck, len(checks))
			copy(bad, checks)
			tampered := make([]byte, len(bad[len(bad)/2].Signature))
			copy(tampered, bad[len(bad)/2].Signature)
			tampered[0] ^= 0xff
			bad[len(bad)/2].Signature = tampered

			require.False(t, verifySerial(bad), "serial must reject a tampered signature")
			require.False(t, verifyBatch(bad), "batch must reject a tampered signature")
		})
	}
}

// benchCorpusSize mirrors the demo repo's rough signature count (≈800 audit
// entries plus ≈250 object footers) so the numbers are representative.
const benchCorpusSize = 1024

func BenchmarkVerifySerial(b *testing.B) {
	checks := buildCorpus(b, 4, benchCorpusSize, 256)
	b.ResetTimer()
	for range b.N {
		if !verifySerial(checks) {
			b.Fatal("corpus should verify")
		}
	}
}

func BenchmarkVerifyBatch(b *testing.B) {
	checks := buildCorpus(b, 4, benchCorpusSize, 256)
	b.ResetTimer()
	for range b.N {
		if !verifyBatch(checks) {
			b.Fatal("corpus should verify")
		}
	}
}
