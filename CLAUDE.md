# sesam

Git-based secret management using age encryption with a cryptographically signed audit log.

## Commands

```bash
task test        # run tests (uses gotestsum)
task build       # build the sesam binary
task lint        # run golangci-lint
task coverage    # tests with coverage report (-coverpkg=./... captures testscript subprocess coverage too)
```

## Architecture

Core logic lives in `core`. The CLI lives in `cli/` (`cli/commands/` for handlers, `cli/repo/` for git bootstrap helpers).

### Two operational phases

1. **Init** (`InitAdminUser` / `InitAuditLog`): creates `.sesam/`, generates the admin's signing key, writes the first audit log entry and the trust anchor (`.sesam/audit/init`).
2. **Regular** (`LoadAuditLog` + `Verify`): loads the log, replays it to derive `VerifiedState`, then builds a `SecretManager` or `UserManager` on top.

### Audit log is the source of truth

`VerifiedState` (users, groups, secrets, access lists) is **derived** by replaying the audit log — it is never stored separately. The log is append-only JSONL (`.sesam/audit/log.jsonl`), one encrypted entry per line.

**`log.jsonl` format:**
- Line 1: `base64(age-encrypted 32-byte AES-GCM key)` — re-encrypted atomically when users are added/removed (`WriteAuditKey` / `RotateKey`)
- Lines 2+: AES-GCM encrypted JSON entries (one per line)

**Adding entries:** always go through `VerifiedState.FeedEntry()`. This calls `AuditLog.AddEntry()` with a verify callback that replays the log to confirm the new entry is valid before writing to disk. Never call `verify()` directly from outside.

**Hash chain:** each entry contains the hash of the previous signed entry. The init entry's hash is pinned in `.sesam/audit/init` (the trust anchor) and checked via git history (`verifyInitFileUnchanged`).

**Crash safety:** a single `Write` syscall + `O_SYNC` per entry. Any line that fails to decrypt is surfaced as an error — corrupt trailing entries are rejected, never silently dropped.

### Domain separation

Ed25519 signatures use domain-tagged messages (prefix before signing/verifying):
- `sesam.audit.v1:` — audit log entry signatures
- `sesam.secret.v1:` — sealed file signatures

### Sealed file format (`.sesam`)

`[age ciphertext bytes]\n[JSON secretFooter]`

- `readSignature(fd)` seeks to the last `\n`, parses the JSON footer, returns an `io.LimitReader` over the age portion.
- The hash in the footer covers the age ciphertext bytes **plus** the revealed path, so files cannot be silently moved.

Secrets live at `.sesam/objects/<revealed-path>.sesam`.

### Seal / reveal (not encrypt / decrypt)

- **Seal** = encrypt a plaintext file with age for the allowed recipients, append a JSON `secretFooter` after a `\n`, write atomically via `renameio`.
- **Reveal** = read footer, decrypt age content, verify hash and signature, write plaintext atomically.

### Git filter/diff/merge driver integration

`sesam init` writes three git driver configs (`.git/config` local scope):

| driver | config | purpose |
|---|---|---|
| `filter=sesam-filter` | `smudge = sesam smudge %f`, `clean = cat` | reveal on checkout, store ciphertext as-is |
| `diff=sesam-diff` | `textconv = sesam show` | decrypt for `git diff` display |
| `merge=sesam-merge` | `driver = sesam audit merge %O %A %B %L %P` | merge audit log branches |

`.gitattributes` applies these to:
- `.sesam/objects/**/*.sesam` — filter + diff
- `.sesam/audit/log.jsonl` — merge + diff

**Smudge path:** git passes `%f` (the object path, e.g. `.sesam/objects/secrets/token.sesam`). The smudge handler strips the `.sesam/objects/` prefix and `.sesam` suffix to derive the revealed path, then calls `RevealBlob(sesamDir, ids, src, revealedPath)`.

### Naming

- **tell** = add a user (`user.tell` operation, `DetailUserTell`)
- **kill** = remove a user (`user.kill` operation, `DetailUserKill`)
- The "admin" group is implicit — every secret and every `groupsToMap` call includes it automatically.

## Key types

- `Signer` / `Keyring` — signing (ed25519). One signing keypair per user, stored encrypted with their age key in `.sesam/signkeys/<user>.age`.
- `Identity` / `Recipient` — encryption (age/X25519). Users bring their own age keys (or SSH keys converted to age).
- `SecretManager` — high-level seal/reveal/add/remove for secrets.
- `UserManager` — high-level tell/kill for users.
- `AllRecipients(kr)` — returns every recipient in the keyring; used when re-encrypting the audit key for all active users.

## Ordering in source files

Types and interfaces go first, then implementations grouped by type.

## Testing

Tests in `core/` use helpers from `test_helpers_test.go` and adjacent `_test.go` files:

| helper | location | purpose |
|---|---|---|
| `newTestUser(t, name)` | `test_helpers_test.go` | all key material for a test user |
| `initAuditLog(t, sesamDir, admin)` | `test_helpers_test.go` | fresh audit log with one admin |
| `testGitRepo(t)` | `test_helpers_test.go` | temp dir + `git.PlainInit` + `.sesam` subdirs |
| `testSecretManagerFull(t)` | `test_helpers_test.go` | full manager with one secret, ready for seal/reveal |
| `sealedSecretManager(t)` | `secret_manager_test.go` | like above but secret is already sealed on disk |
| `testSecretManager(t)` | `secret_test.go` | minimal manager (no audit log) for low-level secret tests |
| `testSecret(t, mgr, path, content)` | `secret_test.go` | writes plaintext + returns `*secret` ready to seal |
| `buildTestUserManager(t)` | `user_manager_test.go` | `UserManager` backed by a fresh audit log |

Integration tests (`integration_test.go`) exercise the full init + reload + verify + seal + reveal cycle with real git repos.

CLI integration tests use `testscript` (`cli/testdata/scripts/`). Their subprocess coverage is automatically merged into `-coverprofile` by the go tool — no extra setup needed.
