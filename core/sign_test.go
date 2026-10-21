package core

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndLoadSignKey(t *testing.T) {
	sesamDir := testRepo(t)
	user := newTestUser(t, "alice")

	signer, err := GenerateSignKeyAt(testRoot(t, sesamDir), "", "alice", []age.Recipient{user.Recipient.Recipient})
	require.NoError(t, err)
	require.Equal(t, "alice", signer.UserName())

	loaded, err := LoadSignKey(testRoot(t, sesamDir), "alice", user.Identity)
	require.NoError(t, err)
	require.Equal(t, "alice", loaded.UserName())

	// Cross-verify: sign with generated, verify with loaded's pubkey.
	data := []byte("test data")
	sig, err := signer.Sign(SesamDomainSignSecretTag, data)
	require.NoError(t, err)

	kr := EmptyKeyring()
	kr.SetSignPubKey("alice", loaded.PublicKey())
	who, err := kr.Verify(SesamDomainSignSecretTag, data, sig, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", who)
}

// Signing and verifying must not write through the domain tag. The tags are
// package-level slices, so a tag carrying spare capacity - one edit away -
// would have Seal's parallel workers write their payload into one shared
// backing array. Run under `task test-race`: the append-based version reports
// a write/write race on the tag (and mis-signs on top of it).
func TestSignDomainWithSpareCapacityIsNotShared(t *testing.T) {
	user := newTestUser(t, "alice")

	kr := EmptyKeyring()
	require.NoError(t, kr.SetSignPubKey(user.Name, user.Signer.PublicKey()))

	// Same bytes as the real tag, but with room after them.
	domain := make(SignDomain, 0, 64)
	domain = append(domain, SesamDomainSignSecretTag...)

	const workers = 8
	errs := make([]error, workers)

	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			data := fmt.Appendf(nil, "payload-%d", i)
			sig, err := user.Signer.Sign(domain, data)
			if err != nil {
				errs[i] = err
				return
			}

			who, err := kr.Verify(domain, data, sig, user.Name)
			if err != nil {
				errs[i] = err
				return
			}

			if who != user.Name {
				errs[i] = fmt.Errorf("signature attributed to %q, want %q", who, user.Name)
			}
		}()
	}

	wg.Wait()
	require.NoError(t, errors.Join(errs...))
	require.Equal(t, SesamDomainSignSecretTag, domain, "the tag itself must come back untouched")
}

func TestLoadSignKeyMissing(t *testing.T) {
	sesamDir := testRepo(t)
	user := newTestUser(t, "alice")
	_, err := LoadSignKey(testRoot(t, sesamDir), "alice", user.Identity)
	require.Error(t, err, "should fail when sign key file does not exist")
}

func TestLoadSignKeyWrongIdentity(t *testing.T) {
	sesamDir := testRepo(t)
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	// Generate key encrypted to alice.
	_, err := GenerateSignKeyAt(testRoot(t, sesamDir), "", "alice", []age.Recipient{alice.Recipient.Recipient})
	require.NoError(t, err)

	// Try loading with bob's identity - should fail to decrypt.
	_, err = LoadSignKey(testRoot(t, sesamDir), "alice", bob.Identity)
	require.Error(t, err, "should fail when decrypting with wrong identity")
}

func TestReadAllSignatures(t *testing.T) {
	mgr := testSecretManager(t)

	for _, p := range []string{"secrets/a", "secrets/b", "nested/c"} {
		s := testSecret(t, mgr, p, "content-"+p)
		_, err := sealSecret(mgr, s, mgr.recipientsFor(s), mgr.cryptPath(s), "testuser")
		require.NoError(t, err)
	}

	sigs, err := readAllSignatures(mgr.root)
	require.NoError(t, err)
	require.Len(t, sigs, 3)
}

func TestReadAllSignaturesEmpty(t *testing.T) {
	sesamDir := testRepo(t)
	sigs, err := readAllSignatures(testRoot(t, sesamDir))
	require.NoError(t, err)
	require.Empty(t, sigs)
}

func TestReadAllSignaturesNoObjectsDir(t *testing.T) {
	// When the objects dir doesn't exist at all (e.g. fresh init before any seal).
	sesamDir := t.TempDir()
	sigs, err := readAllSignatures(testRoot(t, sesamDir))
	require.NoError(t, err, "should not fail when objects dir does not exist")
	require.Empty(t, sigs)
}

func TestSignCrossDomain(t *testing.T) {
	sesamDir := testRepo(t)
	user := newTestUser(t, "alice")

	signer, err := GenerateSignKeyAt(testRoot(t, sesamDir), "", "alice", []age.Recipient{user.Recipient.Recipient})
	require.NoError(t, err)
	require.Equal(t, "alice", signer.UserName())

	loaded, err := LoadSignKey(testRoot(t, sesamDir), "alice", user.Identity)
	require.NoError(t, err)
	require.Equal(t, "alice", loaded.UserName())

	data := []byte("test data")
	sig, err := signer.Sign(SesamDomainSignSecretTag, data)
	require.NoError(t, err)

	kr := EmptyKeyring()
	kr.SetSignPubKey("alice", loaded.PublicKey())
	who, err := kr.Verify(SesamDomainSignSecretTag, data, sig, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", who)

	// Has to fail, different domain.
	_, err = kr.Verify(SesamDomainSignAuditTag, data, sig, "alice")
	require.Error(t, err)
}

func TestPruneOrphanSignKeys(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = root.Close() }()

	require.NoError(t, root.MkdirAll(".sesam/signkeys", 0o700))
	for _, u := range []string{"alice", "bob", "carol"} {
		f, err := root.Create(".sesam/signkeys/" + u + ".age")
		require.NoError(t, err)
		require.NoError(t, f.Close())
	}

	pruned, err := PruneOrphanSignKeys(root, "", map[string]bool{"alice": true, "carol": true})
	require.NoError(t, err)
	require.Equal(t, []string{"bob"}, pruned)

	_, err = root.Stat(".sesam/signkeys/bob.age")
	require.True(t, os.IsNotExist(err), "orphan signkey must be removed")
	_, err = root.Stat(".sesam/signkeys/alice.age")
	require.NoError(t, err, "kept signkey must remain")
	_, err = root.Stat(".sesam/signkeys/carol.age")
	require.NoError(t, err)
}

func TestPruneOrphanSignKeysMissingDir(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = root.Close() }()

	pruned, err := PruneOrphanSignKeys(root, "", map[string]bool{})
	require.NoError(t, err)
	require.Empty(t, pruned)
}
