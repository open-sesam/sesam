package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// testUser holds all key material for a test user.
type testUser struct {
	Name       string
	Signer     Signer
	Identity   *Identity
	Recipient  *Recipient
	SignPubKey string // multicode-encoded
}

func newTestUser(t *testing.T, name string) *testUser {
	t.Helper()

	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	id := &Identity{
		Identity: ageID,
		pub:      newStringPubKey(ageID.Recipient().String()),
	}

	recp := &Recipient{
		Recipient:           ageID.Recipient(),
		comparablePublicKey: id.pub,
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer := &ed25519Signer{pub: pub, priv: priv, user: name}
	signPubKey := MulticodeEncode(pub, MhEd25519Pub)

	return &testUser{
		Name:       name,
		Signer:     signer,
		Identity:   id,
		Recipient:  recp,
		SignPubKey: signPubKey,
	}
}

func (tu *testUser) DetailUserTell(groups []string) DetailUserTell {
	return DetailUserTell{
		User:        tu.Name,
		Groups:      groups,
		PubKeys:     []string{tu.Recipient.String()},
		SignPubKeys: []string{tu.SignPubKey},
	}
}

// testRepo creates a temp dir with all required .sesam subdirectories.
func testRepo(t *testing.T) string {
	t.Helper()
	sesamDir := t.TempDir()

	for _, dir := range []string{
		filepath.Join(sesamDir, ".sesam", "objects"),
		filepath.Join(sesamDir, ".sesam", "tmp"),
		filepath.Join(sesamDir, ".sesam", "audit"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	return sesamDir
}

// testKeyring creates a keyring populated with the given users.
func testKeyring(t *testing.T, users ...*testUser) *MemoryKeyring {
	t.Helper()
	kr := EmptyKeyring()
	for _, u := range users {
		kr.AddSignPubKey(u.Name, u.Signer.PublicKey())
		kr.AddRecipient(u.Name, u.Recipient)
	}

	return kr
}

// initAuditLog creates a fresh audit log with the given user as admin.
func initAuditLog(t *testing.T, sesamDir string, admin *testUser) *AuditLog {
	t.Helper()

	al, err := InitAuditLog(
		sesamDir,
		admin.Signer,
		Recipients{admin.Recipient},
		admin.DetailUserTell([]string{"admin"}),
	)
	if err != nil {
		t.Fatal(err)
	}

	return al
}

// loadAuditLog loads an existing audit log using the given users' identities.
func loadAuditLog(t *testing.T, sesamDir string, users ...*testUser) *AuditLog {
	t.Helper()

	ids := make(Identities, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.Identity)
	}

	al, err := LoadAuditLog(sesamDir, ids)
	if err != nil {
		t.Fatal(err)
	}

	return al
}

// writeSecret creates a plaintext file at revealedPath inside the repo.
func writeSecret(t *testing.T, sesamDir, revealedPath, content string) {
	t.Helper()
	fullPath := filepath.Join(sesamDir, revealedPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(fullPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// testGitRepo creates a temp dir initialized as a git repo with .sesam subdirs.
func testGitRepo(t *testing.T) (string, *git.Repository) {
	t.Helper()
	sesamDir := testRepo(t)

	repo, err := git.PlainInit(sesamDir, false)
	if err != nil {
		t.Fatal(err)
	}

	return sesamDir, repo
}

// gitCommitAll stages all files and commits them.
func gitCommitAll(t *testing.T, repo *git.Repository, msg string) {
	t.Helper()
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := wt.Add("."); err != nil {
		t.Fatal(err)
	}

	_, err = wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@test.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

// testSecretManagerFull creates a SecretManager backed by a full audit log and verified state.
func testSecretManagerFull(t *testing.T) *SecretManager {
	t.Helper()
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	// Add a secret to the audit log.
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: "secrets/test",
		Groups:       []string{"admin"},
	}), nil)

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{
		RootHash:    "placeholder",
		FilesSealed: 0,
	}), nil)

	kr := EmptyKeyring()
	state := &VerifiedState{auditLog: al, keyring: kr}
	if err := verify(state); err != nil {
		t.Fatal(err)
	}

	mgr, err := BuildSecretManager(
		sesamDir,
		Identities{admin.Identity},
		admin.Signer,
		kr,
		al,
		state,
	)
	if err != nil {
		t.Fatal(err)
	}

	return mgr
}
