# Verify

Since `sesam` is a tool focused on security, we need to constantly check whether we have been compromised
and warn the user. There are several checks that are being run on commits, which will be explained in this chapter.

```admonish warning
TL;DR:

We recommend running `sesam verify --all` as part of your CI/CD pipeline.
If it fails, you should fail the pipeline and let a human look over it.
```

## Audit Log

`sesam` is [based on an audit log](./design.md) that keeps track of all
modifications made in the repository. It can be useful to view it, if you're
unsure on what happened:

```bash
sesam log
 # [...]
 #7  ✓  2026 Jun 21 12:37  sahib@online.de  sealed 1 secret FiCsnuSN
 #6  →  2026 Jun 21 12:37  sahib@online.de  renamed bg.png → background.png
 #5  ✓  2026 Jun 21 12:35  sahib@online.de  sealed 2 secrets FiDhxZqF
 #4  +  2026 Jun 21 12:35  sahib@online.de  added bg.png (admin)
 #3  ✓  2026 Jun 21 12:34  sahib@online.de  sealed 1 secret FiCtifM1
 #2  +  2026 Jun 21 12:34  sahib@online.de  added README.md (admin)
 #1  ★  2026 Jun 21 12:34  sahib@online.de  initialized repo 4e0d7eb1
```

The audit log is a list of entries, each describing a change to the repository.
It is stored in encrypted fashion in `.sesam/audit/log.jsonl`. Each entry is
linked to the previous one via a hash and protected by a signature of the user
that made the change.

Additionally, we store the hash of the first entry as a trust anchor and can
check over git history that it was not modified. This makes truncating the log harder.

On almost every `sesam` command we will verify the integrity of the log and
rebuild the expected state from it. Failure to do so is fatal and requires
investigation on why the state could not be verified.

On every seal we will also compute a *root hash*, i.e. a hash that is built
from the signed footer of every sealed secret. We attach this *root hash* to each
seal entry (e.g. the `FiCsnuSN` above) and verify by default that the latest root
hash is still valid. If it is not, it means you have a mismatch between what the
audit log says should be stored and what is actually on disk.

There are only a few valid cases where this might happen (e.g. when running a
`git checkout` without the hooks provided by `sesam`), but if it happens you
can work around it by running this:

```bash
# re-seal and write correct root hash:
sesam --verify-mode no-disk seal
```

If it happened on a multi-user system, you should be wary - maybe somebody tried to sneak in some changes.

## Extended checks

Apart from this default verification we have the `sesam verify` command. It
will do some slightly more costly checks to see if anything malicious might be
going on.

### Audit Log truncation check

Check git history from `HEAD` back to the init commit to see if each older audit
log is a prefix of the newer one. The log is completely linear, so this catches
malicious truncation events. If an older audit log cannot be decrypted by the
current identity, verification stops at that point without treating it as a failure.

This will be run on `sesam verify --truncate`

### File integrity check

The `age` encryption format cannot give us a way to detect if a file was
silently swapped with another one. One could still try to replace it with
another file. Luckily, `sesam` writes a signed footer with hashes for each file
and thus allows catching deviations from the expected state, including missing
sealed files, unexpected extra sealed files, invalid footer signatures, unauthorized
sealers, and root-hash mismatches.

This will be run on `sesam verify --integrity`

### Forge synchronicity check

When using forge user IDs like `github:sahib`, `sesam verify --forge-check`
re-fetches the live keys and checks them against the values recorded in the
audit log when the user was added. A mismatch is not a security issue per-se -
it can also mean a user has rotated their keys upstream and might have locked
themselves out - but it is something an admin should investigate.

This will be run on `sesam verify --forge-check`

It does not give `sesam verify` a non-zero exit code if keys are not in sync.

### Key re-use check

Each user should have their own keys. `sesam` already refuses to add a
recipient that another user already holds, but a hand-edited or tampered audit
log could still smuggle in a shared key. This check re-scans the resulting
keyring and flags any public key that maps to more than one user.

This will be run on `sesam verify --key-reuse`

### Running everything

`sesam verify --all` (also the default when no check is selected) runs all of
the above at once. It exits non-zero if any check other than the forge
synchronicity check fails.
