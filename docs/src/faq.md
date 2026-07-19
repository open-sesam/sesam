# Troubleshooting &amp; FAQ

This page collects expected problems and questions that might arise.

## I cloned the repo but my secrets aren't there

A fresh clone does **not** reveal secrets on its own. The git integration lives
in the local git config and hooks, which are never part of a clone. After
cloning you have to install them once:

```bash
# Reveal the secrets explicitly:
$ sesam open
# Make sure it gets done automatically on the next checkout.
# If the repo already exists, this just re-installs the git-integration.
$ sesam init
```

```admonish note
Config-based hooks need **git ≥ 2.54**. On older git the hooks are skipped and
you have to run `sesam open` / `sesam seal` yourself. `sesam doctor` tells you
what is and isn't wired up.
```

Only secrets you can actually decrypt are written out. The rest stay sealed
with no plaintext pendant. That is expected, not an error (see
[Managing users](./users.md)).

## `git diff` shows my secret in plaintext - is that a leak?

No. On `init`, `sesam` registers a `diff` textconv (`sesam show`) in
`.gitattributes`. When you run `git diff`, git pipes the encrypted object
through it so you see a **readable, local-only** diff. Nothing plaintext is
written to git - the committed blob under `.sesam/objects/` stays encrypted.

## `sesam` says the repository is locked

`sesam` takes a lock file (`.sesam.lock`, next to `.sesam`) so two processes
never write the state at once. If you see a lock error, another `sesam` command - or a git hook that calls one - is still running.
Wait for it, or raise the timeout:

```bash
$ sesam --lock-timeout 30s open
```

If a process was killed hard and left the lock behind, remove `.sesam.lock`
manually **after** making sure nothing else is running.

## I removed a user with `kill` but they can still read secrets

This is expected and it is sadly just a fact of life.
You have to consider all secrets they had access to as lost (see [rotation](./rotation.md)).

`sesam kill` removes the user from the current state so they can no longer be
added as a recipient of *future* seals. It does **not** revoke access to what
they could already read:

1. Ciphertext they already pulled stays decryptable with their identity key,
   forever.
2. Past commits still contain those secrets encrypted to their old key.

```admonish danger title="kill is not revocation"
To actually revoke access, follow `kill` with a rotation of every secret the
user was able to read. Then re-deploy the secrets.
```

## `sesam verify` fails after a pull or merge

Don't deploy off it yet, but also don't panic just yet. A failure means the
verified state and what's on disk disagree; the cause is usually one of:

- **A broken push (DoS).** A collaborator committed inconsistent state (bad
  signature, stale root hash, malformed log). Annoying, not an attack. Revert
  to a good commit and have them re-run the operation correctly.
- **A stale on-disk root hash.** A partial checkout can restore an object
  without its audit log. `sesam open` followed by `sesam seal` reconciles it;
  the hooks normally do this for you on checkout.
- **Genuine tampering.** Truncation or substitution of the audit log (see below).

If verify reports the **audit log was truncated** or the **init file changed**,
that points at a rewritten history (typically a force-push). `sesam` can only
detect this by comparing against an older copy — a local clone, a CI checkout, a
colleague's repo. Compare against a known-good copy before trusting anything, and
disable force-push at your forge (see [Initialisation](./init.md)).

## I ran `sesam uninstall` and now re-`init` fails with "init file check: … has uncommitted changes"

This is because the verification logic of `sesam` asserts that
`.sesam/audit/init` always contains the very same content for the life-time of
a `git` repository. This is designed in that way to avoid history rewrites.

In practice, you cannot re-init the same repository at the same place. If this
proves to be a problem in actual use we'd like to hear from you. There might be
ways to relax the conditions here.

For now, you can do the following:

- Init the new `sesam` repo in a different (sub-)directory.
- Rewrite the git history so that the `sesam` repo never "existed".
- Revert to a state before you've deleted the repo.

None of them is a perfect solution of course.

## How do I reveal secrets in CI/CD without a human?

Give the pipeline a dedicated machine identity (its own `age`/SSH key, told into
the groups it needs) and point `sesam` at it explicitly so nothing prompts on a
missing TTY:

```bash
$ sesam --identity /secure/ci-key.age verify --all
$ sesam --identity /secure/ci-key.age open
```

Run `sesam verify --all` **before** you deploy and let a non-zero exit stop the
pipeline. This is the integrity-vs-availability trade-off: a stronger check
means a broken or tampered repo fails the build instead of shipping stale or
malicious secrets. A scheduled verify job that alerts you before deploy time is
the best of both worlds.

```admonish note
If `sesam` hangs or errors asking for a key in CI, it is running without a TTY
and without a usable identity. Pass `--identity` (and, for a non-root `.sesam`,
`--sesam-dir`) explicitly.
```

## I get an error about a root hash check

You might encounter one of these errors:

```text
✘ failed to verify audit log: reading signatures for root hash check: unexpected end of JSON input
✘ failed to verify audit log: root hash mismatch: log says abc, disk says xyz (try --verify-mode no-disk)
```

This means the audit log remembers a different state than what is on disk.

If you are sure that everything is fine (i.e. nobody swapped secrets when you were not on your watch)
then you can run:

```bash
$ sesam --verify-mode no-disk seal
```

This will re-seal existing revealed paths and add a new root hash to the audit log.
If it still is not fixed, an admin might have to run the same command (as you can only seal files that you have access to).

## I have entered my identity passphrase, but it's outdated

You can clear the cached passphrase in the system keyring:

```bash
$ sesam keyring clear
```

Next run will query the password again.

## My shell wants to correct `sesam` to `.sesam`

i.e. you get something like this:

```bash
$ sesam ls
 zsh: correct 'sesam' to '.sesam' [nyae]?
```

Not something we can fix on our end, but it's a buggy correction setup.
There are a couple workarounds:

**zsh**

- `unsetopt correct` - disables all command corrections.
- `export CORRECT_IGNORE_FILE='.*'`  - disable correction for all dot-files.
- `export CORRECT_IGNORE_FILE='.sesam'`  - disable correction for `.sesam` only.

All of them need to be added to your `.zshrc` to stick.

If you have other shells here that act up, feel free to write us.
