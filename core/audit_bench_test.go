package core

import (
	"fmt"
	"testing"
)

// buildBenchAuditLog initializes an audit log with the admin and `entries`
// additional secret-change entries, all written to disk. It returns the
// sesam dir and the admin user (whose identity decrypts the audit key).
func buildBenchAuditLog(b testing.TB, entries int) (string, *testUser) {
	b.Helper()

	sesamDir := testRepo(b)
	admin := newTestUser(b, "admin")
	al := initAuditLog(b, sesamDir, admin)
	b.Cleanup(func() { _ = al.Close() })

	// Entry 1 is the init entry; add the rest as distinct secret changes,
	// which the admin is always allowed to make.
	for i := 1; i < entries; i++ {
		if _, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
			RevealedPath: fmt.Sprintf("secrets/bench/secret-%06d", i),
			AccessGroups: []string{"admin"},
		}), nil); err != nil {
			b.Fatalf("seed entry %d: %v", i, err)
		}
	}

	return sesamDir, admin
}

// BenchmarkAuditLog measures loading a large audit log from disk and replaying
// it into a VerifiedState - the work that happens on every sesam invocation.
func BenchmarkAuditLog(b *testing.B) {
	const entries = 20_000

	sesamDir, admin := buildBenchAuditLog(b, entries)
	ids := Identities{admin.Identity}

	// Sanity check the seeded log before timing anything.
	al, err := LoadAuditLog(testRoot(b, sesamDir), ids)
	if err != nil {
		b.Fatalf("initial load: %v", err)
	}
	if got := len(al.Entries); got != entries {
		b.Fatalf("seeded %d entries, loaded %d", entries, got)
	}
	if _, err := VerifyChain(al, EmptyKeyring(), nil); err != nil {
		b.Fatalf("initial verify: %v", err)
	}
	_ = al.Close()

	// Load only: read every line from disk and decrypt it.
	b.Run("Load", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			al, err := LoadAuditLog(testRoot(b, sesamDir), ids)
			if err != nil {
				b.Fatal(err)
			}
			if err := al.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})

	// Load + verify: the full cost of deriving the trusted state from disk.
	b.Run("LoadAndVerify", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			al, err := LoadAuditLog(testRoot(b, sesamDir), ids)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := VerifyChain(al, EmptyKeyring(), nil); err != nil {
				b.Fatal(err)
			}
			if err := al.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})
}
