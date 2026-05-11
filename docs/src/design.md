# Design

TODO: Those are rough remarks. Clean up later and draw some diagrams.

## Architecture

- We use [age](https://github.com/FiloSottile/age) for hybrid encryption/decryption.
  - `age` supports its own key format as well common ssh keys.
  - It also supports Postquantum crypto already.
  - age's [plugin system](https://github.com/FiloSottile/awesome-age#plugins) allows integration of Yubikeys and much more.
  - We don't roll our own crypto, which is always a good thing.
- The handling of elaborate private key setups is to be done by the user to allow flexibility.
  - Exception: We support passphrase protected ssh keys as common use case.
- Users have a public key they are referenced by.
  - Supported keys: age native (X25519) or SSH keys.
  - Users can also use forge-usernames (e.g. github:sahib)
  - All users know the public key of all other users through the config.
  - User are identified by private key ("identity").
  - Users are put into groups.
  - Only the pre-existing admin group may add new users/groups.
  - Every secret has a list of groups it may be accessed by.
  - Only users having access to a secret can change this access list.
- Age keys support no signing, we therefore generate a ed25519 signing key for each user.
  - Keys are stored as `.sesam/signkeys/$user.age`.
- All encrypted files and repository state are stored in a `.sesam` directory.
- The `sesam.yml` file (see example in this repo) is declarative, i.e.
- All operations that are changing the repository state are logged in an audit log.
  - All entries in the audit log are signed and reference the previous entry via hash.
  - This makes the log append-only and verifiable.
  - We also can re-construct the supposed state from the log.
  - This state could be also diffed to the existing `sesam.yml` to find diffs.
  - Diffs can be therefore detected in case of verify (i.e. malicious changes).
  - Diffs can also be applied in case of local changes before push (`sesam apply`)
  - Verification is run before any important operation.

| Operation       | Needs                          | Source                                          |
|-----------------|--------------------------------|-------------------------------------------------|
| Seal (encrypt)  | Recipients' age public keys    | Repo config                                     |
| Reveal (decrypt)| User's age identity            | Local (key file, SSH key, plugin — user's choice)|
| Sign            | Ed25519 signing private key    | Decrypt `.sesam/signkeys/$user.age` via age     |
| Verify          | Ed25519 signing public key     | Repo (plaintext)                                |

## Configuration

See sesam.yml for an annotated example file.

### Rotation

We want it to make it possible to rotate and exchange existing secrets easily.
Supported types would be for example:

- Ssh key:
  - Generate: ssh-keygen (take settings over from existing?)
  - Exchange: ssh into server, add to authorized_keys, verify it works, remove old one, verify it still works and that old one does not work.
  - Config: Host, ssh-user, key-gen settings?
- Password:
  - Generate: just a simple pwgen
  - Exchange: Hmm. Probably via a script?
  - Config: zxcvbn min score, alterantively length and other pwgen settings.
- Template:
  - Meta secret type that allows generation inside an existing file.
  - Basically a "container" for one or several other secrets.
- AWS/Github/[...] keys. Needs per-service integration if possible.
  - Integration should be optional and not baked into the main binary.
- Custom
  - Generate: script
  - Exchange: script

The steps of a rotation would be:

- plan: Show which secrets are rotated, which are exchanged.
- exec: Execute the plan above.
- todo: keep track of manual work that could not be automated with command to mark items done.

### Other notes

- We should have some git integration:
  - do an automatic git pull to check for changes
  - allow use of gitattributes to show local diffs between encrypted files. (smudge/clean filters)
  - Integrate as git command (`git sesam`)
  - Encourage using signed commits when pushing something with sesam
- We should be able to reveal/seal whole directories where it makes sense.
- Force pushes should be disabled for the repo and users should be made aware.
- We should allow working in parallel where possible (e.g. encrypt only files that changed).
- Implement command to view ownership of files easily.
- Adding/Removing persons require re-encryption of all files.
- sesam should support several .sesam dirs per git repo, `.git` and `.sesam` don't need to be in the same folder.
- README: Make clear that this is not vibe coded. Also mention that we think about rewriting in Rust after 1.0
- We should use multicode to encode hashes, priv/pub keys and signatures: <https://github.com/sj14/multicode>
  This way we can figure out if a byte blob is a signature, hash or something else.

### Verify

Checks the integrity of the entire repository without revealing secrets.
Implicitly called after pull, reveal or seal. Should also run in CI.

#### Audit log

Append-only, hash-chained log of all state-changing operations.
Stored under `.sesam/audit/log.json` (chunking planned for later).

Entry structure:

| Field        | Description                                              |
|--------------|----------------------------------------------------------|
| `seq_id`     | Monotonic sequence number (starting at 1)                |
| `prev_hash`  | SHA3-256 (multihash-encoded) of the previous entry       |
| `operation`  | Operation type (see below)                               |
| `time`       | ISO8601 UTC timestamp                                    |
| `changed_by` | User that executed the operation                         |
| `detail`     | Operation-specific data (see below)                      |
| `signature`  | Ed25519 signature over all other fields (canonical JSON) |

Operation types:

| Operation        | Detail fields                                  | Notes                                           |
|------------------|------------------------------------------------|-------------------------------------------------|
| `init`           | InitUUID, Admin (embedded UserTell)            | Trust root. Pins first admin. See below.        |
| `user.tell`      | User, PubKeys, SignPubKeys, Groups             | Must be signed by an admin.                     |
| `user.kill`      | User                                           | Must not remove last user or last admin.        |
| `secret.change`  | RevealedPath, Groups                           | Add or update a secret and its access list.     |
| `secret.remove`  | RevealedPath                                   | Only users with access may remove.              |
| `seal`           | RootHash, FilesSealed                          | Hash over all sorted `.sig.json` files.         |

Group membership is part of the `user.tell` detail. There are no separate
group operations. Changing a user's groups means `user.kill` + `user.tell`.
Admin status is determined by membership in the "admin" group.

Key rotation is also handled as `user.kill` + `user.tell`. The log doubles as
key archive: past `user.tell` entries record which signing and encryption keys
were valid at which point, so old signatures stay verifiable.

#### Authorization

Every entry that modifies users or secrets must be signed by an admin. The
entry's `signature` field proves who wrote it. During verification we check
that the signer was a member of the "admin" group at that point in the log.

The first admin is established by the `init` entry itself (embedded `Admin`
field). There is no separate bootstrap `user.tell`.

#### Trust anchor (`.sesam/audit/init`)

`sesam init` writes the SHA3-256 hash of the init entry (seq 1) to
`.sesam/audit/init`. This file is created once and must never change.

During verification, the hash of the current seq 1 entry is compared to this
file. If they differ, the log was rebuilt from scratch. CI can additionally
check that `git log -- .sesam/audit/init` has exactly one commit.

Does not protect against `git push --force` (Eve can rewrite the first commit
and make everything consistent). Force push protection is outside sesam's
threat model and should be enforced at the forge level.

#### Tamper detection

Three checks work together:

1. **Chain integrity**: `prev_hash` of each entry must equal the SHA3-256 of
   the previous entry. Any modification, insertion or deletion breaks the chain.

2. **Trust anchor**: The hash of the seq 1 entry must match `.sesam/audit/init`.
   If not, the entire log was replaced.

3. **State-vs-log consistency**: Replaying the log must produce a model that
   matches the actual state on disk:
   - Users and their groups must match `sesam.yml`.
   - Secrets and their access lists must match `sesam.yml`.
   - The `RootHash` in the latest `seal` entry must match the hash computed
     from the `.sig.json` files on disk.

Attack scenarios and which check catches them:

- Eve modifies the config but skips the log: state-vs-log fails (replayed
  model does not match `sesam.yml`).
- Eve adds forged log entries: signature check fails (signer is not an admin).
- Eve replaces the entire log: trust anchor check fails (init hash does not
  match `.sesam/audit/init`).
- Eve replaces encrypted files: the `RootHash` in the seal entry no longer
  matches the `.sig.json` files.

#### Branching and merging

The audit log is linear and hash-chained. When two branches diverge, each
appends its own entries with valid chains. On merge, git produces conflict
markers in `log.jsonl`. Sesam detects and resolves these automatically —
no separate merge tool is needed.

##### Conflict detection

`LoadAuditLog` detects git conflict markers (`<<<<<<<`) in the JSONL file.
It parses both sides, finds the common prefix (entries shared before the
fork), and produces two divergent tails: "ours" (HEAD) and "theirs"
(incoming branch).

##### Replay strategy

The merge is linearized: "ours" entries are kept in place, "theirs" entries
are replayed on top. Each replayed entry gets a new `seq_id`, `prev_hash`,
and is re-signed by the merging user. The merging user does not need admin
privileges — the original authorization is established by the `changed_by`
field and git history (similar to how the init file's integrity relies on
git history).

If replay fails (e.g. both branches added the same user, or a replayed
entry references a user that was removed on "ours"), the merge is aborted
with a diagnostic. The user must resolve the conflict on one branch first,
then retry.

##### Secret content conflicts

Encrypted files (`.age`, `.sig.json`) are marked as `binary` in
`.gitattributes` (set up by `sesam init`), so git does not produce conflict
markers for them — it keeps "ours" and marks the path as conflicted.

If the same secret was sealed with different content on both branches, the
replay renames the incoming version:

```
secrets/db_pass              ← ours (unchanged)
secrets/db_pass.theirs       ← theirs (renamed during replay)
```

Both are valid secrets in the audit log with their own access groups. The
user inspects both, keeps the one they want, and removes the other via
`sesam rm`. After cleanup, a `sesam seal` produces a consistent state.

##### .gitattributes

`sesam init` should generate:

```
.sesam/objects/**/*.age binary
.sesam/objects/**/*.sig.json binary
```

This prevents git from attempting text merges on encrypted content.

#### Additional checks

- For each secret: `.sig.json` signature and ciphertext hash must be valid.
- For each user: at least one public key must match the configured identity.
- Freshly added secrets: warn if the adding user has no access to them.

## Overview

```
┌─────────────────────────────────────────────────────────┐
│                     SecretManager                       │
│          ties everything together for a session         │
└────┬──────────┬───────────────┬─────────────────┬───────┘
     │          │               │                 │
     ▼          ▼               ▼                 ▼
┌────────┐ ┌────────┐    ┌──────────┐    ┌───────────────┐
│Identity│ │ Signer │    │ Keyring  │    │ VerifiedState │
│ your   │ │ signs  │    │everyone's│    │ "what should  │
│ private│ │ entries│    │public    │    │  the repo     │
│ key(s) │ │&secrets│    │keys      │    │  look like?"  │
└───┬────┘ └───┬────┘    └────┬─────┘    └───────┬───────┘
    │          │              ▲                   ▲
    │          │              │ keys added        │ built by
    │          │              │ during replay     │ replaying
    │          ▼              │                   │
    │       ┌─────────────────┴───────────────────┘─────┐
    │       │ AuditLog                                  │
    │       │  append-only, hash-chained, signed        │
    │       │  entries each entry is one of:            │
    │       │   - Init (+first admin)  - UserTell/Kill  │
    │       │   - SecretChange/Remove  - Seal           │
    │       └───────────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────────────────┐
│ Secret                                         │
│  Seal():   encrypt + sign ──► .age + .sig.json │
│  Reveal(): decrypt via identity                │
│  recipients come from VerifiedState + Keyring  │
└───────────────────────┬────────────────────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ SecretSignature   │
              │  per-file hash    │
              └────────┬──────────┘
                       │
                       ▼
              BuildRootHash()
               combined hash of all .sig.json,
               stored in Seal entries

Verify():
 1. check .sesam/audit/init not tampered (git history)
 2. replay log: check chain, signatures, authorization
 3. compare resulting state against repo on disk
```
