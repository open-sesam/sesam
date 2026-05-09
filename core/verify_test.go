package core

import (
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
		al, err := InitAuditLog(sesamDir, admin.Signer, Recipients{admin.Recipient}, tell)
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
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
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
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
		}), nil)

		carol := newTestUser(t, "carol")
		al.AddEntry(bob.Signer, newAuditEntry("bob", &DetailUserTell{
			User: "carol", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: carol.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{carol.SignPubKey},
		}), nil)

		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("self add", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "admin", Groups: []string{"admin"},
			PubKeys: []UserPubKey{{Key: admin.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{admin.SignPubKey},
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
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
		}
		al.AddEntry(admin.Signer, newAuditEntry("admin", tell), nil)
		al.AddEntry(admin.Signer, newAuditEntry("admin", tell), nil)

		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})
}

// --- verifyUserKill tests ---

func TestVerifyUserKillBasic(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
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
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
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
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
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

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: "secrets/db", Groups: []string{"dev"},
	}), nil)

	state := verifyState(t, al, EmptyKeyring())
	s, exists := state.SecretExists("secrets/db")
	require.True(t, exists)
	require.Equal(t, "secrets/db", s.RevealedPath)
}

func TestVerifySecretChangeNegative(t *testing.T) {
	t.Run("empty groups", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
			RevealedPath: "secrets/db", Groups: []string{},
		}), nil)
		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})

	t.Run("no access to existing secret", func(t *testing.T) {
		sesamDir := testRepo(t)
		admin := newTestUser(t, "admin")
		al := initAuditLog(t, sesamDir, admin)

		bob := newTestUser(t, "bob")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "bob", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
		}), nil)

		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
			RevealedPath: "secrets/db", Groups: []string{"ops"},
		}), nil)

		// Bob (dev) tries to change ops-only secret.
		al.AddEntry(bob.Signer, newAuditEntry("bob", &DetailSecretChange{
			RevealedPath: "secrets/db", Groups: []string{"dev"},
		}), nil)

		require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
	})
}

func TestVerifySecretChangeUpdate(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: "secrets/db", Groups: []string{"dev"},
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: "secrets/db", Groups: []string{"ops"},
	}), nil)

	state := verifyState(t, al, EmptyKeyring())
	s, _ := state.SecretExists("secrets/db")
	require.Contains(t, s.AccessGroups, "ops")
}

// Regression: the verify layer must reject any RevealedPath that contains
// path-traversal components. Previously only the high-level API validated
// the path, so a hand-crafted entry could seed state.Secrets with
// "../../.ssh/authorized_keys", causing RevealAll to write outside the repo.
func TestVerifySecretChangeRejectsPathTraversal(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: "../../.ssh/authorized_keys",
		Groups:       []string{"admin"},
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
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
	}), nil)

	// Bob (dev) tries to register a brand-new secret restricted to "ops".
	al.AddEntry(bob.Signer, newAuditEntry("bob", &DetailSecretChange{
		RevealedPath: "secrets/ops-db", Groups: []string{"ops"},
	}), nil)

	require.Error(t, verifyStateFail(t, al, EmptyKeyring()))
}

// --- verifySecretRemove tests ---

func TestVerifySecretRemoveBasic(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: "secrets/db", Groups: []string{"dev"},
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
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
		}), nil)

		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
			RevealedPath: "secrets/db", Groups: []string{"ops"},
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
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
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
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
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
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
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
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
		}), nil)

		carol := newTestUser(t, "carol")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "carol", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: carol.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{carol.SignPubKey},
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
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
		}), nil)

		carol := newTestUser(t, "carol")
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
			User: "carol", Groups: []string{"dev"},
			PubKeys: []UserPubKey{{Key: carol.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{carol.SignPubKey},
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
			PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
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

	entry := &auditEntrySigned{auditEntry: auditEntry{ChangedBy: "alice", SeqID: 1}}
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
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
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

	state, err := Verify(al, EmptyKeyring())
	require.NoError(t, err)
	require.Len(t, state.Users, 1)
}

func TestVerifyExportedRootHashMatch(t *testing.T) {
	sesamDir, repo := testGitRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: "secrets/test", Groups: []string{"admin"},
	}), nil)

	writeSecret(t, sesamDir, "secrets/test", "content")
	kr2 := testKeyring(t, admin)
	s := &secret{
		Mgr: &SecretManager{
			SesamDir: sesamDir, Identities: Identities{admin.Identity},
			Signer: admin.Signer, Keyring: kr2,
		},
		RevealedPath: "secrets/test",
		Recipients:   kr2.Recipients([]string{"admin"}),
	}

	sig, err := s.Seal("admin")
	require.NoError(t, err)

	rootHash := buildRootHash([]*secretFooter{sig})
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{
		RootHash: rootHash, FilesSealed: 1,
	}), nil)

	gitCommitAll(t, repo, "full setup")

	state, err := Verify(al, EmptyKeyring())
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

	_, err := Verify(al, EmptyKeyring())
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
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: "secrets/db", Groups: []string{"dev"},
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{
		RootHash: "test-root-hash", FilesSealed: 1,
	}), nil)

	loaded, err := LoadAuditLog(sesamDir, Identities{admin.Identity})
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
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
	}), nil)

	carol := newTestUser(t, "carol")
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "carol", Groups: []string{"ops"},
		PubKeys: []UserPubKey{{Key: carol.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{carol.SignPubKey},
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: "secrets/db_pass", Groups: []string{"dev"},
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: "secrets/api_key", Groups: []string{"ops"},
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
