# sesam

Git-based secret management using age encryption with a cryptographically signed audit log.

## Commands

```bash
task test        # run tests (uses gotestsum)
task build       # build the sesam binary
task lint        # run golangci-lint
task coverage    # tests with coverage report
```

## Architecture

Core logic lives in `core`.

### Two operational phases

1. **Init** (`InitAdminUser` / `InitAuditLog`): creates `.sesam/`, generates the admin's signing key, writes the first audit log entry and the trust anchor (`.sesam/audit/init`).
2. **Regular** (`LoadAuditLog` + `Verify`): loads the log, replays it to derive `VerifiedState`, then builds a `SecretManager` or `UserManager` on top.

### Audit log is the source of truth

`VerifiedState` (users, groups, secrets, access lists) is **derived** by replaying the audit log — it is never stored separately. The log is append-only JSONL (`.sesam/audit/log.jsonl`), one signed entry per line.

- **Adding entries:** always go through `VerifiedState.FeedEntry()`. This calls `AuditLog.AddEntry()` with a verify callback that replays the log to confirm the new entry is valid before writing to disk. Never call `verify()` directly from outside.
- **Hash chain:** each entry contains the hash of the previous signed entry. The init entry's hash is pinned in `.sesam/audit/init` (the trust anchor) and checked via git history.
- **Crash safety:** a single `Write` syscall + `O_SYNC` per entry. Partial trailing entries are detected and truncated on load with a warning.

### Domain separation

Ed25519 signatures use domain-tagged messages (prefix before signing/verifying):
- `sesam.audit.v1:` — audit log entry signatures
- `sesam.secret.v1:` — sealed file signatures

### Seal / reveal (not encrypt / decrypt)

- **Seal** = encrypt a plaintext file with age for the allowed recipients, write `.sesam` (which is like .age but with signature json at the end)
- **Reveal** = decrypt, verify signature, write plaintext back

### Naming

- **tell** = add a user (`user.tell` operation, `DetailUserTell`)
- **kill** = remove a user (`user.kill` operation, `DetailUserKill`)
- The "admin" group is implicit — every secret and every `groupsToMap` call includes it automatically.

## Key types

- `Signer` / `Keyring` — signing (ed25519). One signing keypair per user, stored encrypted with their age key in `.sesam/signkeys/<user>.age`.
- `Identity` / `Recipient` — encryption (age/X25519). Users bring their own age keys (or SSH keys converted to age).
- `SecretManager` — high-level seal/reveal/add/remove for secrets.
- `UserManager` — high-level tell/kill for users.

## Ordering in source files

Types and interfaces go first, then implementations grouped by type.

## Testing

Tests in `core/` use helpers from `test_helpers_test.go`:
- `newTestUser(t, name)` — generates all key material for a test user
- `initAuditLog(t, sesamDir, admin)` — creates a fresh audit log with one admin
- `testSecretManagerFull(t)` — full manager with one secret, ready for seal/reveal tests
- `sealedSecretManager(t)` — like above but the secret is already sealed on disk

Integration tests (`integration_test.go`) exercise the full init + reload + verify + seal + reveal cycle with real git repos.
