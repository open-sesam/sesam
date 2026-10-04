
# NAME

sesam - Manage encrypted secrets in git repositories

# SYNOPSIS

sesam

```
[--askpass]=[value]
[--clipboard-copy-cmd]=[value]
[--clipboard-paste-cmd]=[value]
[--cpuprofile]=[value]
[--help|-h]
[--identity|-i]=[value]
[--lock-timeout]=[value]
[--memprofile]=[value]
[--no-color]
[--quiet|-q]
[--sesam-dir|-r|--repo]=[value]
[--verbose|-v]
[--verify-mode]=[value]
[--version]
```

# DESCRIPTION

**`sesam` is a tool for managing secrets in git.**

Let's discuss the sentence above some more:

- `secrets`: Are just regular files that contain something precious to you. They are on your filesystem *revealed* (decrypted) and *sealed* (encrypted).
- `managing`: Making sure *sealed* and *revealed* are in sync and allow the user to define who has access to what secret.
- `in git`: Developers are naturally used to `git` and `sesam` integrates well with it.

### Intro

Software projects often need to store and load several secrets such as
database passwords, certificates, API keys or other credentials. Those secrets
should be stored encrypted and only be accessible to the users that actually
need them.

`sesam` allows leveled access with multiple users to those encrypted secrets
and gives you a simple interface to manage both users and secrets.

In short, `sesam` fits well the [GitOps model](https://about.gitlab.com/topics/gitops/) of infrastructure.

> **Note**
>
> The term *user* does not necessarily refer to a person. A user can also be a machine, like a server where `sesam` is installed.

### What is a secret manager?

You might think of a password manager now, which is not too far off - `sesam`
can indeed also be used as a password manager. A password manager is usually
targeted at managing individual secrets, while a secret manager is focused on
sharing selected secrets with other users in a team and machines. If you
already know what a secret manager is then you might be interested in Why we
built another tool.

### Features

### Security

- Every write is recorded, signed and verified by an audit log.
- Support for SSH keys, age keys and age plugin identities.
- Different access levels through user groups.
- Encrypted at rest; only secret paths and group membership are visible in the repo.
- Safe to use (hard to accidentally push unencrypted secrets)
- Per-secret integrity checks with root-hash verification.

### Convenience

- Forge recipient shortcuts for GitHub, GitLab and Codeberg.
- Both declarative (config) and imperative (CLI) workflows possible.
- Familiarity to `git` users.
- Decentralized & offline ready.
- Scriptable via CLI interface.
- Somewhat fast encryption and decryption.¹
- Almost zero dependencies.


### Git Integration

- Secrets are naturally versioned.
- Allows viewing local diffs of secrets and the audit log.
- Hooks keep revealed files in sync on checkout, pull and merge.
- Merging of secrets is supported.

### Planned features

- Support for rotation and swapping of secrets ([Plan](https://github.com/open-sesam/sesam/issues/40))
- More tooling so that `sesam` can be well used as password manager.
- Deeper support for `env` files.

# GLOBAL OPTIONS

**--askpass**="": Askpass helper for encrypted identities \[$SESAM_ASKPASS, $GIT_ASKPASS, $SSH_ASKPASS\]

**--clipboard-copy-cmd**="": Command reading the secret on stdin, instead of the system clipboard \[$SESAM_CLIPBOARD_COPY_CMD\]

**--clipboard-paste-cmd**="": Command printing the clipboard, instead of the system clipboard \[$SESAM_CLIPBOARD_PASTE_CMD\]

**--cpuprofile**="": Write a CPU profile of this invocation to `FILE` (pprof format) \[$SESAM_CPUPROFILE\]

**--help, -h**: show help

**--identity, -i**="": Path to the age identity (can be given several times) \[$SESAM_ID, $SESAM_IDENTITY\]

**--lock-timeout**="": Repository lock wait timeout (e.g. 5s, 30s, 2m) \[$SESAM_LOCK_TIMEOUT\] (default: 5s)

**--memprofile**="": Write a heap profile at exit to `FILE` (pprof format) \[$SESAM_MEMPROFILE\]

**--no-color**: Disable color always \[$NO_COLOR, $SESAM_NO_COLOR\]

**--quiet, -q**: Print less log output

**--sesam-dir, -r, --repo**="": Directory where .sesam lives \[$SESAM_DIR\] (default: ".")

**--verbose, -v**: Print more log output

**--verify-mode**="": Adjust how strong or weak the disk state is verified ('all', or 'no-disk') (default: "all")

**--version**: Print the version and exit

# COMMANDS

### init

Initialize sesam in the current repository

**--help, -h**: show help

**--install-alias**: Make it possible to call sesam as `git sesam`

**--install-diff**: Install diff support in repo git config

**--install-hooks**: Install pre-commit and post-checkout git hooks (needs git >= 2.54.0)

**--install-merge**: Install merge support in repo git config

**--user, -u**="": Initial admin user name (if not given, git config is used to guess)

### uninstall

Removes git integration and optionally all of the sesam repo

**--all**: Also remove sesam.yml and .sesam/

**--help, -h**: show help

**--no-ask**: Do not ask for confirmation for --all

### verify

Verify sesam signatures and encryption state

**--all**: Run all verifications

**--config**: Check sesam.yml does not declare a change that already arrived committed (not part of --all)

**--forge-check**: Verify the forge public keys did not change since adding users

**--help, -h**: show help

**--integrity**: Check file integrity on disk

**--json**: Print output as JSON

**--key-reuse**: Double-check that no key is re-used between users

**--truncate**: Verify the audit log was not truncated over history

### clean

Remove revealed plaintext and other untracked files from the sesam directory

**--aggressive**: Also delete other untracked files (similar to `git clean -fdx`)

**--dry-run**: Do not actually delete, just print what would be deleted

**--help, -h**: show help

**--unsealed**: Also delete plaintext whose content is not sealed: edited since, or never

### doctor

Check sesam installation for possible problems

**--help, -h**: show help

### hook

Util to manage git hooks

**--help, -h**: show help

### hook pre-commit

Execute the pre-commit hook - meant to be run by git!

**--help, -h**: show help

### hook post-checkout

Execute the post-checkout hook - meant to be run by git!

**--help, -h**: show help

### hook pre-merge-commit

Execute the pre-merge-commit hook - meant to be run by git!

**--help, -h**: show help

### hook post-merge

Execute the post-merge hook - meant to be run by git!

**--help, -h**: show help

### hook install

Make sure the git hooks are installed

**--help, -h**: show help

### hook uninstall

Uninstall any hooks

**--help, -h**: show help

### add

Add a secret file or directory at `PATH`

**--group, -g**="": Group assignment for the secret (repeatable) - 'admin' is implicit

**--group-add, -G**="": Add to the secret's existing groups instead of replacing them

**--help, -h**: show help

**--nested**: When the secret lives in a subdirectory, give that directory its own sesam.yml instead of adding it to the main file

**--no-seal**: Do not run 'sesam seal' afterwards - useful when batching

**--seal-all, --all**: Seal every secret from its plaintext as it is, stale and diverged ones included

### rm

Remove a secret file or directory

**--force, -f**: Also remove the revealed secrets

**--help, -h**: show help

### mv

Move a secret file or directory to a new name

**--help, -h**: show help

**--nested**: When the secret lives in a subdirectory, give that directory its own sesam.yml instead of adding it to the main file

### edit

Open secret in $VISUAL or $EDITOR and immediately seal it afterwards

**--editor**="": Editor executable to use instead of $VISUAL or $EDITOR

**--help, -h**: show help

**--seal-all, --all**: Seal every secret from its plaintext as it is, stale and diverged ones included

### seal

Encrypt and sign changed secrets

**--clean**: Delete revealed secret files after successful seal

**--help, -h**: show help

**--seal-all, --all**: Seal every secret from its plaintext as it is, stale and diverged ones included

### open, reveal

Decrypt all secrets available to the current user

**--all, -a**: Reveal every secret, overwriting plaintext you edited

**--help, -h**: show help

### status, s

Show overview over repo state (revealed, sealed, unmanaged, ...)

**--all, -a**: Also show in-sync secrets and unmanaged files (hidden by default)

**--diff, -d**: Show the actual diff using git (extra args are passed to git)

**--help, -h**: show help

**--json**: Print output as JSON

**--users, -u**: Show users instead of groups

### show

Show objects managed by sesam

**--alsoclip, -C**: Copy to clipboard and print to stdout

**--clip, -c**: Copy to clipboard instead of printing to stdout

**--help, -h**: show help

**--ttl, -t**="": How long to wait before clearing the clipboard (0 disables) (default: 45s)

**--wait, -w**: Wait for the password to be cleared instead of forking to the background

### ls, list-secrets

List known secrets and metadata

**--help, -h**: show help

**--json**: Print output as JSON

### rotate

Plan and execute secret rotation

**--help, -h**: show help

### tell

Add a person to a group and re-encrypt files

**--group, -g**="": Group assignment (repeatable)

**--group-add, -G**="": Add to the user's existing groups instead of replacing them

**--help, -h**: show help

**--no-seal**: Do not run 'sesam seal' afterwards - useful when batching

**--recipient**="": Recipient key spec (e.g. github:alice) - can be given several times

**--seal-all, --all**: Seal every secret from its plaintext as it is, stale and diverged ones included

**--user, -u**="": User name to add or update

### kill

Remove a person from the sesam repo entirely

**--help, -h**: show help

**--no-seal**: Do not run 'sesam seal' afterwards - useful when batching

**--seal-all, --all**: Seal every secret from its plaintext as it is, stale and diverged ones included

**--user, -u**="": User name to remove

### user, u

User management commands

**--help, -h**: show help

### user list, ls

List persons, groups, and access

**--help, -h**: show help

**--json**: Print output as JSON

### user change-groups

Change the groups a user is in

**--group, -g**="": Group assignment for the user (repeatable) - 'admin' is implicit

**--group-add, -G**="": Add to the user's existing groups instead of replacing them

**--help, -h**: show help

**--no-seal**: Do not run 'sesam seal' afterwards - useful when batching

**--seal-all, --all**: Seal every secret from its plaintext as it is, stale and diverged ones included

**--user, -u**="": Which user should be changed

### user add-recipient, ar

Add a recipient to an existing user

**--help, -h**: show help

**--no-seal**: Do not run 'sesam seal' afterwards - useful when batching

**--recipient**="": Recipient key spec (e.g. github:alice) - can be given several times

**--seal-all, --all**: Seal every secret from its plaintext as it is, stale and diverged ones included

**--user, -u**="": Which user receives the new recipient

### user remove-recipient, rr

Remove a recipient from an existing user (may not be the last one)

**--all-except, -a**: Delete all except the recipients named by --recipient

**--help, -h**: show help

**--no-seal**: Do not run 'sesam seal' afterwards - useful when batching

**--recipient**="": Recipient key spec (e.g. github:alice) - can be given several times

**--seal-all, --all**: Seal every secret from its plaintext as it is, stale and diverged ones included

**--user, -u**="": Which user looses the specified recipient

### user regen-sign-key, rsk

Regenerate the signing key of a specific user

**--help, -h**: show help

**--user, -u**="": Regenerate the signing key for a user

### user rename

Give a user a different name

**--help, -h**: show help

### config

Config management commands

**--help, -h**: show help

### config apply

Apply config differences to audit log and metadata

**--force, -f**: Also apply changes that arrived already committed (see the docs on modified configs)

**--help, -h**: show help

**--json**: Print output as JSON

**--no-seal**: Do not run 'sesam seal' afterwards - useful when batching

**--seal-all, --all**: Seal every secret from its plaintext as it is, stale and diverged ones included

### config diff

Show the diff between config and actual state (extra args are passed to git)

**--help, -h**: show help

**--json**: Print output as JSON

**--validate**: Fail if 'sesam config apply --force' would refuse the config (dry run, needs admin rights)

### config print

Print the whole config as one document, includes resolved (YAML, or JSON with --json)

**--help, -h**: show help

**--json**: Print output as JSON

### config reset

Derive config from audit log

**--force, -f**: Rewrite sesam.yml from scratch when it cannot be repaired in place, losing comments and descriptions

**--help, -h**: show help

**--json**: Print output as JSON

### apply

alias for `sesam config apply`

**--force, -f**: Also apply changes that arrived already committed (see the docs on modified configs)

**--help, -h**: show help

**--json**: Print output as JSON

**--no-seal**: Do not run 'sesam seal' afterwards - useful when batching

**--seal-all, --all**: Seal every secret from its plaintext as it is, stale and diverged ones included

### id

Identify the current user by age identity

**--help, -h**: show help

**--json**: Print output as JSON

### keyring

Keyring utils

**--help, -h**: show help

### keyring clear

Clear cached passphrases from the keyring

**--help, -h**: show help

### log

Show the audit log of secret changes

**--full, -f**: Show full timestamps and ids instead of shortened ones

**--help, -h**: show help

**--json**: Print output as JSON

### help, h

Show help for a command, or the built-in manual

**--man**: Show the built-in manual instead of the command overview

# GETTING STARTED

### Prerequisites

`sesam` relies a lot on `git` for some functionality. You can either **use an existing repository** to manage your secrets in
or you can create a whole new one. If you use an existing repository we recommend an empty sub-directory to manage
your secret files in. The `.sesam` directory does not need to be on the same level as the `.git` folder.

### Creating a new repository

In the folder you've selected run:

```bash
sesam init --identity ~/.ssh/whatever-key-you-want
```

This command will do the following:

- Create a folder `.sesam/` in the current directory.
- Create a default config file in `sesam.yml`. It is a declarative config describing the state we want in our repo.
- Create a `.gitignore` that ignores everything but `.sesam/` and `.sesam.yml`. This is to protect revealed secret so they **never get accidentally added to git**.
- Create `.gitattributes` that tells `git` what to do with the encrypted files.
- It will also do a couple other `git` operations that are described here.
- It will also create a first secret: `README.sesam`. Read it for a very condensed version of this tutorial.
- We will guess the initial user's name from your `git config`. If you want a different name then use the `--user` parameter or rename later.
- The initial user will automatically be an `admin` user. `sesam` has the concept of users with different access levels.
- Every user needs an **identity** - a cryptographic way to prove he is this specific user.
  In the example above we used an ssh key.

> **Note**
>
> Hi! In those notes we're trying to give you some background information on why things are the way they are.
> You probably won't lose too much required information if you don't read those boxes, but we recommend to do so.
> You may remember that using `git` got easier when you understood how it works under the hood? Anyway, let's continue:
>
> The `--identity` option has to be passed to most `sesam` commands. Typing this out is tedious, but luckily we support
> specifying almost all command line flags as environment variable. If you place this in your `.bashrc` (or whatever you use),
> then you never need to specify the identity path again:
>
> `export SESAM_IDENTITY=~/.ssh/whatever-key-you-want`
>
> The rest of this guide assumes that you've exported an environment variable.

### Identities

An *identity* is just a fancy name for a private key that is attached to a specific user.
`sesam` supports the following keys as identity:

- SSH Keys (RSA and ed25519, may be passphrase protected)
- [Age Keys](https://github.com/FiloSottile/age) (generated by `age-keygen`, also maybe be passphrase protected)
- Age plugin identities

If you want to use several of them you can also pass `--identity` (or short
`-i`) several times. Then `sesam` will use all of them for encryption and
decryption.

> **Warning**
>
> **You are responsible for storing your identity in a safe place.** You should
> not store it as part of the sesam repository.

If you want to know as what user you identify as, just type:

```bash
sesam id
bob
```

With the `--json` option you also get the public keys you are using:

```bash
sesam id --json
{
  "name": "bob",
  "groups": [
    "admin"
  ],
  "sign_pub_key": [
    "7QEg5yp1mHH3sy/3AOhBIaNNbZPh7cVlifod+04wzutudko="
  ],
  "recipients": [
    {
      "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN5VzGK/HxjYdIjBnRi6Nq7/0ydsKpX3uk1gu/ywUDJj",
      "source": "manual"
    }
  ]
}
```

> **Note**
>
> We try to be very script-friendly - you will find that most commands support a
> `--json` switch that can then be piped to helpers like `jq` easily.

### Passphrase protected identities

Both `ssh` and `age` support encrypting keys at rest with a passphrase. To
unlock them before use we have to ask the user what the passphrase is. This can
be done either:

1. By asking the user directly on terminal when we detect such a key.
2. By reading the passphrase from the OS keyring (e.g. where it was stored from last time)
3. By using an `askpass` program like `ssh-askpass`, `systemd-askpass` or similar that may ask the user via alternative UI.

The OS keyring is only used as a convenience cache. On Linux this means a
Secret Service provider such as GNOME Keyring, KWallet, or another compatible
daemon must be running. If no compatible keyring is available, `sesam` still
works; it will just ask for the passphrase again next time.

For option 3 you need a compatible program installed and have set any of those variables to the name of the program, so `sesam` knows what to call:

- `SESAM_ASKPASS` (or `--askpass` global option)
- `GIT_ASKPASS` - used in `git` context.
- `SSH_ASKPASS` - used in `git` and `ssh` context.

This is especially important if you want to use the git integration from an IDE - here `sesam` won't have a terminal it can use.
We also honor the related `*_ASKPASS_REQUIRED` variable (i.e. `SESAM_ASKPASS_REQUIRED`, `GIT_ASKPASS_REQUIRED`, `SSH_ASKPASS_REQUIRED`) which can be set to the one those values:

- `never`: Never ask via `askpass`. Disables it effectively.
- `prefer`:  If possible, use the graphical interface.
- `force`: Use it even if have a terminal available that we could ask from.

You don't need to set it though, we will use a sensible default.

Your desktop environment might already set these environment variables.
If it does not, install a program like `ksshaskpass` and set `SESAM_ASKPASS=ksshaskpass`.

### Recipients

Every user of `sesam` has at least one **recipient**. Think of it as the public part to the identity. While only you possess your **identity**, everyone has access to all **recipients**. With **recipients** we can control which secrets are accessible for which users: a secret that should be accessible by Alice and Bob simply gets encrypted with the set of recipients of both users.

### Shell completion

We have support for shell completion for most popular shells thanks to the [urfave/cli package](https://cli.urfave.org/v3/examples/completions/shell-completions/).

```bash
# Choose your shell:
source <(sesam completion bash)
source <(sesam completion zsh)
source <(sesam completion fish)
```

This will enable it only for the current shell. Put it in your shell config (`.bashrc`, `.zshrc`, ...) to make it permanent.
Some day this might be pre-installed for you. When this day comes we document it here.

### `git push --force` and `sesam`

The tamper detection of `sesam` assumes **linear, append-only history**. The audit log
is verified by walking git history and checking that the log at each commit is a
strict prefix of the log at the next - it may grow, but never shrink or change
underneath you. The `init` UUID pinned in the first commit anchors that chain.

A force-push breaks the assumption. By rewriting history it can drop or replace
commits, so a truncated or substituted audit log can be made to look like the
legitimate tip. `sesam` can still *detect* this if it has an older copy to compare
against (a local clone, a CI checkout, another collaborator's repo), but it
cannot detect it from the rewritten remote alone.

> **Warning**
>
> Treat force-push as out of scope for sesam's guarantees. Disable it at the forge
> for any branch that carries a `.sesam` directory:
>
> - **GitHub/Gitea:** enable branch protection and forbid force-push.
> - **GitLab:** mark the branch protected with "Allowed to force push" off.
> - **Self-hosted:** `receive.denyNonFastForwards = true`, or a pre-receive hook.
>
> If a force-push does happen, do not trust the remote state. Compare against a
> known-good clone and run `sesam verify --all` before relying on any secret.
>
> The linear-history requirement is usually the better default anyway, and most
> forges make it a one-click setting.
>
> If the force pushed did only affect files out of sesam, then we should be fine.
>
> `- -force-with-lease` makes no difference here by the way.

### Calling the doctor

If you are unsure if there's something wrong with your installation of `sesam`, then run this:

```bash
sesam doctor
```

This will check the installation and print any issue along with tips on how to fix them.

### Uninstalling `sesam`

If you want to get rid of `sesam` then you can just run `sesam uninstall`.
This will by default remove all git integration that was previously installed
(i.e. remove our `.gitignore` changes, `.gitattributes` and `.git/config`).

If you also want to get rid of all the `sesam.yml` files and `.sesam/` directory
then run `sesam uninstall --all`. That will ask you though.

# MANAGING SECRETS

### Adding a secret via CLI (imperative)

> **Note**
>
> All secrets must be in the same folder as `sesam.yml` or below it.
> We do not support adding secrets outside of the sesam repository.
> Attempts to do so will error out.

If you have a secret at `path/to/secret`, then having it managed by `sesam` is only a matter of this command:

```bash
sesam add path/to/secret --group deploy
```

This will:

1. Record that this file is now managed by `sesam` by adding it to the audit log.
2. Encrypt the file and place it in `.sesam/objects`. This is what is being pushed in the end.

If you omit the `--group` parameter then only the `admin` group will have access to the file.
You can change this at any point by just re-running the `add` command with any groups you want to set.

Overall the workflow looks like this:

```
      ┌─────────────────┐   git add   ┌─────────────────┐    seal     ┌─────────────────┐
      │  git objects    │◄────────────┤  sesam objects  │◄────────────┤ revealed files  │
      │  .git/objects   ├────────────►│ .sesam/objects  ├────────────►│ in worktree     │
      └─────────────────┘   checkout  └─────────────────┘   reveal    └─────────────────┘
```

What this means for you:

- The revealed files are ignored by git.
- Commands like `git log` will print paths like `.sesam/objects/secret.txt` but not `secret.txt`. This is because
  the actual revealed file is of course not tracked.
- If you want to run `git` commands explicitly on secrets, you have to run e.g. `git log .sesam/objects/secret.txt` not `git log secret.txt` therefore.

### Adding a secret via config (declarative)

Adding secrets via CLI is nice for scripts. `sesam` also supports describing
the desired state in a declarative way via `sesam.yml`. If you executed the
above command you will notice the secret was added already to the config:

```yaml
secrets:
  - path: path/to/secret
    access: [deploy]
    desc: Where it used, who owns it, Contact...
```

If you did not run the `add` command above, then you can also add the entry manually and then run:

```bash
sesam apply
```

This will automatically check what the state is in the repo and how it differs
from the state in the config. The changes are then resolved by adding/removing
secrets or adding/removing users. Either all of them are recorded or none is,
so a step that cannot be carried out leaves the repository as it was.

To see the difference before applying it, use `sesam config diff`. It renders
`sesam.yml` against the state the audit log describes, using whatever diff
tooling your git is configured with.

> **Warning**
>
> `sesam apply` only carries out changes that are still uncommitted in your
> working tree. A config change that arrived with a `git pull` is refused - see
> Applying a changed config.

### Adding multiple secrets

You can also add whole directories, if you need to:

```bash
tree dir/of/secrets
.
├── some_file
└── sub
    └── another_file
sesam add --nested dir/of/secrets
tree dir/of/secrets
.
├── sesam.yml
├── some_file
└── sub
    ├── another_file
    └── sesam.yml
```

This will create a config hierarchy of `sesam.yml` files in the config:

```yaml
# Main sesam.yml:
secrets:
  - include: dir/of/secrets
```

```yaml
# dir/of/secrets sesam.yml:
secrets:
  - include: sub
  - path: some_file
```

```yaml
# sub sesam.yml:
secrets:
  - path: another_file
```

Once done you can also add descriptions to the files in the config or do more fine-tuning with the available config keys.

> **Note**
>
> If you ever create new files in the sub directories they do not automatically get added.
> Instead you need to run `sesam add` again. This will also remove secrets that are not there anymore, if any.
> In that sense, it works a bit like `git add`.

### Modifying secrets

Running `sesam add` will work here too, similar to `git add`. By default this will also re-seal the secrets,
except if you pass `--no-seal`.

If you want to change the access groups of a user, then just pass a different set of `--group / -g` flags.
Note that this will overwrite the existing groups. If you would rather like to append, then use `--group-add / -G`.

### Getting an overview

If you need to see which files were modified but not yet sealed you can use `sesam status`:

```bash
# with --all you will only see the modified files,
# without it only those that changed in some way.
sesam status --all
.
├─ M README.md (admin)
├─ ✓ bg.png (admin)
╰─ services/
   ├─ ✓ gateway.env (admin)
   ╰─ ✓ registry.env (admin)
  1 modified · 3 in sync

```

This will show you files you edited directly without calling `sesam add` on them.

The letter says what happened to a secret since its plaintext and its sealed
object were last written together. `sesam` works that out from the object
versions `git` holds, so nothing has to be remembered on your machine:

- `M` modified: you edited the plaintext. `sesam seal` takes it.
- `S` stale: the object moved on (a pull, checkout or merge) and the plaintext is the old version. `sesam reveal` takes it; `sesam seal` leaves it alone.
- `!` diverged: both at once, seen during a merge or by the hooks. Pick a side with `sesam reveal --all` or `sesam seal --all`.
- `R` recipients changed: the content agrees, but who may read it changed. `sesam seal` re-encrypts it.
- `U` conflicted: a merge left conflict markers in the plaintext.

### Removing secrets

If you have deleted files you can run this:

```bash
sesam rm files/ dir/
```

> **Warning**
>
> Please do not delete secrets just with `rm`. This will just remove the revealed file, but the
> sealed file in `.sesam/` will still exist. On the next `sesam open` it will suddenly be back.

### Moving secrets

Probably not very surprising by now, but we have a `mv` command as well:

```bash
sesam mv old_name new_name
```

> **Warning**
>
> The same warning as with `sesam rm` applies: Please do not just move the file
> with `mv`. This will just move  the revealed file to a new name, but the sealed
> file in `.sesam/` will still exist. On the next `sesam open` it will suddenly
> be back with the old path.

### Listing secrets

```bash
sesam ls
├── README.sesam
└── dir
    └── of
        └── secrets
            ├── some_file
            └── sub
                └── another_file
```

You can also use the ``--json`` switch to print it in a more scriptable way.

# MANAGING USERS

### Managing users via config

As mentioned during Initialisation there is always at least one admin user.
At the time you created your repo, you would see something like this in your config:

```yaml
users:
  - name: bob
    desc: Bob the Builder
    key:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6VzKY/HxjYdIjBnRi6Nq7/0ydsKpX3uk1gu/ywUDJj
groups:
  admin:
    - bob
```

As you can see, `bob` is an admin. Let's assume we are building a cloud backend
in a team and want to give some users access to the required secrets for
deployment. We can do so by adding some more users and a new group:

```diff
   users:
     - name: bob
       desc: Bob the Builder
       key:
         - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6VzKY/HxjYdIjBnRi6Nq7/0ydsKpX3uk1gu/ywUDJj
+    - name: alice
+      desc: Mrs. Wonderland
+      key:
+        - github:alice
+    - name: peter
+      desc: Peter Lustig
+      key:
+        - file://keys/peter.txt
   groups:
     admin:
       - bob
+    deployment:
+      - alice
+      - peter
```

We've used two new ways to fetch the keys:

* `github:alice` will use all configured public keys of the GitHub user
`alice` (actually it's just the `https://github.com/alice.keys`). Many forges support an API to fetch this information. You can also use
`gitlab:` or `codeberg:`. This makes adding new users really easy, as you most
likely already know the user name of your peer on your favorite forge.
The public key will be fetched only once initially and the result is cached. Apart from the first time there is no online access required therefore.
* Peter on the other hand might not have an forge account. Maybe he also has an awful long RSA key that you don't want to put in the config verbatim. In this case you can just create a file in the repo and add it there. We recommend adding an exception to `.gitignore` if you want to push those public keys.
* The key of `bob` was derived from the identity used during init. If you use the same public key for (e.g.) your GitHub account you can also write something like `github:bob` there.

### Applying a changed config

Once we've changed the config we can use this command, which should be familiar by now. This will then adjust the repository state accordingly:

```bash
sesam apply
+ user alice (groups: deployment, keys: github:alice)
+ user peter (groups: deployment, keys: file://keys/peter.pub)
applied 2 changes
```

Every step is recorded in the audit log.
If one cannot be carried out, nothing is written and the reason is printed.
`sesam.yml` itself is never rewritten by `apply`, so your comments and descriptions
stay. To see what would happen first, run `sesam config diff`.

> **Changes have to come from your working tree**
>
>
> A config you `git pull`ed should not be applied without manual approval.
> Read through it and make sure any changes made are fine (`git log -p -- sesam.yml`).
> If the changes are looking good, use `sesam apply --force`.

Went too far while editing? `sesam config reset` rewrites `sesam.yml` from the
audit log, throwing your edits away.
It edits the file in place, so your comments and descriptions survive, but a config
too broken to read can only be replaced from scratch, so reset asks for `--force`
before doing that.

Changing groups later works the same way.

> **Note**
>
> Only admins may add/change other user and groups. If you're not an admin (determined by your identity) you will get an error.

----

Adding users and groups does not automatically give them access to secrets.
We have to specify for each secret which groups have access to them (Reminder: the `admin` group has access always). Let's add them:

```diff
secrets:
  - path: some_password.txt
+   access:
+   - deployment
```

If you run `sesam apply` again, other users will have access. You have to commit (if you did not use ``--commit`` of course) and push it via git, of course. Then the others can pull the changes:

```bash
# on the laptop of alice:
git pull
sesam open
```

### Managing users via CLI

You can have the same effect without editing configs:

```bash
# Add users like above:
sesam tell --user alice --recipient "github:alice"
sesam tell --user peter --recipient "file://keys/peter.txt"
# --group  can be given several times:
sesam add some_password.txt --group deploy --group ops
```

`sesam tell` also works on a user that already exists: it changes their groups
(`--group` replaces the set, `--group-add`/`-G` adds to it) and adds any
`--recipient` you pass. For an existing user both are optional, but you have to
give at least one. Creating a brand-new user requires a `--recipient`; groups
are optional there too.

```bash
# alice already exists: set her groups to just "ops"
sesam tell --user alice --group ops
# ...and additionally put her in "deploy" without dropping "ops"
sesam tell --user alice --group-add deploy
# register a second device key for her without touching her groups
sesam tell --user alice --recipient "file://keys/alice-laptop.txt"
```

Files automatically get re-encrypted ("sealed") after each operation.
If you want to work in batches then add `--no-seal` and seal explicitly once at the end.

### Removing users

Removing users is also something only admins can do:

```bash
sesam kill --user alice
```

This will remove `alice` from all the access, delete any group that is now empty and then re-encrypt all files.

> **Note**
>
> You can not remove the last admin. There has to be always at least one user.

### Auxiliary operations

There are a couple of operations that are worth knowing they exist,
but since they are not daily drivers we only briefly mentioned them.
By now you should be able to guess what they do:

```bash
# List all users
sesam user list
```

```bash
# Change the groups a user is in
sesam user change-groups --user alice --group a --group b

# Append, instead of overwriting:
sesam user change-groups --user alice --group-add c

# Can be also done by tell for existing users:
sesam tell --user alice --group a --group b

```

```bash
# Add one or more recipients to an existing user
sesam user add-recipient --user alice -r "..." -r "..."

# Can be also done by tell for existing users:
sesam tell --user alice --recipient "..."
```

```bash
# Remove one or more recipients from an existing user.
sesam user remove-recipient --user alice -r "..."

# Alternatively, invert it and delete all but the specified:
sesam user remove-recipient --user alice --all-except -r "..."
```

```bash
# Regenerate the signing key of a user (seldomly useful)
sesam user regen-sign-key --user alice
```

```bash
# Rename an existing user.
sesam user rename ellisch alice
```

# GIT INTEGRATION

`sesam` integrates tightly with `git`.
This page gives you an overview what is being set-up for you by default.

### Diffing

On `init`, we setup [diff filters](https://git-scm.com/book/en/v2/Customizing-Git-Git-Attributes) via the `.gitattributes` file.
This means that `git` will pipe every change through `sesam show` before showing as diff.

Try for example committing your secrets and then run `git log -p` to see how secrets evolved over time.

Files you don't have access to will not be shown.

### Hooks

`git >= 2.54.0` [supports setting multiple hooks for a single
event](https://github.blog/open-source/git/highlights-from-git-2-54/#h-config-based-hooks)
in its config without requiring an external hook manager. We make use out if it
by registering the following hooks by default on `sesam init`. If you do not
wish to install them, then please pass `--install-hooks=false` to the `init`
command. You can also call `sesam hook install` or `sesam hook uninstall` at
any point later.

If you have an older version of `git` you can still hook up those by calling
`sesam hook pre-commit` or `sesam hook post-checkout` on the equally named hook.
Use either a hook manager of your choice or directly work with `.git/hooks`.

Keep in mind that hooks are always per-repo! They need to be set up freshly for
every new clone.

### `post-checkout`

When you check out an older state you likely want also the revealed files to have the content committed at this time.
This hook does the following:

- If we're checking out a branch, tag or other ref: revealed secrets that no longer exist on the new state are removed, and the ones the checkout replaced are revealed freshly.
- If we're checking out a single file or directory: the checked-out secrets are revealed and re-sealed, so they get added to the audit log.

Plaintext you edited but did not seal is never touched by either. `git` cannot
warn about it (revealed files are gitignored), so the hook tells you what it kept:
`sesam seal` keeps your version, `sesam reveal --all` takes the checked-out one.

> **Note**
>
> This is not being called when running `git reset`. If you do this, you should probably run `sesam open` explicitly.

### `post-merge`

`git` does not run `post-checkout` after a merge, and a fast-forward merge (what
`git pull` usually is) runs no other hook either. Without this hook the revealed
files would keep the pre-merge content while the sealed objects moved on - and
the next `sesam seal` would write the stale plaintext back over what you pulled.

This hook reveals the secrets whose objects the merge changed, as long as their
plaintext still holds the pre-merge version. Edited plaintext stays and is named,
a conflict you are mid-way through resolving included.

### `pre-commit`

When you commit you most likely want to make sure that all files you've edited in the worktree are sealed (i.e. `sesam status` shows nothing)
and no accidental tampering was done. This is done by this hook before every commit:

- Reveal secrets whose object changed while their plaintext did not (might happen on merge or single-file checkout)
- Seal all files you edited.
- Refuse when a secret changed on both sides - you edited it and `git` replaced its object - and name both ways out.
- Run `sesam verify --all`.

If errors happen the commit will be aborted and you can check if there is indeed something wrong.
If you decide that all is good you can still continue with `git commit --no-verify` (this skips running the hook temporarily).

### Merging branches

> **Warning**
>
> As the other hooks, git >= 2.54 is required!
> Merging without will inevtiably cause a broken repo state.

Encrypted files appear as random bytes. Even the very same content can result
in totally different ciphertext. That's not something that `git merge` can
handle - it needs to see the revealed files. Of course, only authorized users
have access to it.

Luckily, we have the audit log. This log has been modified in both branches and
can be traced to a common root. Assuming a user has sufficient privileges (i.e.
an admin) then those changes be replayed on top of each other and the merged
state can be revealed. If there are actual conflicts, then `sesam` will leave
the conflict markers in the revealed secrets - you can then continue to work
out the conflicts like you are used from `git`. The next commit will again
trigger the `pre-commit` hook that will in turn make sure that all secrets are
conflict marker free and sealed.

To merge two branches you go mostly the normal git flow:

1. `git merge <branch>`
2. Check the output of the `sesam` merge driver, clear conflicts if necessary.
3. `git commit`

One notable difference from the normal flow: There will be never an automatic
merge commit. To give you a chance to review the automated decision making done
by the merge driver we will always tell `git` that there were conflicts, so
don't be afraid of those messages.

What happens on the technical level:

- For every sealed secret we do a three-way merge of the revealed contents and write the merged content to the revealed path.
  If there are conflicts, the revealed path will contain conflict markers.
- The changes of the incoming audit log will be "rebased" (in the sense of re-done) onto our existing audit log.
  Conflicts are automatically resolved by heuristics, which are supposed to capture what a sensible user would usually do.
  (e.g. if a user was removed on our side, but updated on the other then the remove will win).
- The audit log will get a `merge` entry that will explain any conflicting decisions.
  If you want to see what secrets conflicted, then run `sesam status`.
- Added/changed/removed signing keys might still be present after the `git merge`. Those will be cleaned up by the `pre-commit` hook.
- The state on the disk might not fully reflect yet what the audit log says. An explicit seal is required, which is done automatically
  for you by the `pre-commit-hook` fired by `git commit`.
- If you forgot to clean a secret up (i.e. it still contains merge markers), the `pre-commit-hook` will stop you.

To understand better we should look at an example (slightly contrived) session:

```shell
$ mkdir merge-example && cd merge-example
# Create git & sesam & initial commit:
$ git init
$ sesam init
$ git add . && git commit -am 'base'

# on feature branch:
$ git checkout -b feature
$ echo hello > secret.txt
$ sesam add secret.txt --group admin
$ sesam tell --recipient github:Johnny2210 --group admin
$ git add . && git commit -am 'add secret.txt and Johnny'

# on main branch (derived from base):
$ git checkout main
$ echo world > secret.txt
$ sesam add secret.txt --group admin
$ sesam tell --recipient github:adelbables --group admin
$ git add . && git commit -am 'add secret.txt and Adel'

# Actual merge action:
$ git merge feature
sesam: automatically merging revealed file secret.txt; 1 conflict - please fix manually.
sesam: automatically merging revealed file README.md; no conflicts, but access to it changed on both sides
sesam: it will be sealed with the merged recipients when you commit
sesam: both sides changed the audit log.
sesam: the audit log was therefore semantically merged.
sesam:
sesam:
sesam: NOTE: git may tell you the operation failed below.
sesam:       this is only to give you a chance to review the repo state before continuing.
sesam:
sesam: resolve any conflicts mentioned above (if any), then check with `sesam status`.
sesam: finish this merge with `git commit`.
sesam: in case you don't have the git integration installed run `sesam hook pre-commit` directly.
sesam: if you're unsure what any of this means, you can also start over with `git merge --abort` and then `sesam reveal --all`
Auto-merging .sesam/audit/log.jsonl
Auto-merging .sesam/objects/README.md.sesam
Auto-merging .sesam/objects/secret.txt.sesam
CONFLICT (add/add): Merge conflict in .sesam/objects/secret.txt.sesam
Auto-merging sesam.yml
Automatic merge failed; fix conflicts and then commit the result.


# You will see merge 
$ cat secret.txt
<<<<<<< ours/secret.txt
world
||||||| origin/secret.txt
=======
hello
>>>>>>> theirs/secret.txt

$ sesam status
.
├─ M README.md (admin)
╰─ U secret.txt (admin)
  1 conflicted · 1 modified

a merge is in progress.
  resolve the conflicted (U) secrets above
  and finish with `git commit`
  or start over with `git merge --abort` followed by `sesam reveal --all`

# Do a content merge:
$ echo 'hello world' > secret.txt

$ sesam status
.
├─ M README.md (admin)
╰─ M secret.txt (admin)
  2 modified

a merge is in progress.
  nothing left to resolve - review the merged secrets
  and finish with `git commit`
  or start over with `git merge --abort` followed by `sesam reveal --all`

# Audit log was automatically merged:
$ sesam log
#9  ⋈  2026 Aug 16 12:46  sahib  merged audit log (1 applied, 3 dropped)
#8  +  2026 Aug 16 12:44  sahib  told Johnny2210 into admin
#7  ✓  2026 Aug 16 12:45  sahib  sealed 2 secrets FiDFG71BQ9PX
#6  +  2026 Aug 16 12:45  sahib  told adelbables into admin
#5  ✓  2026 Aug 16 12:45  sahib  sealed 2 secrets FiCe0k67WVO6
#4  +  2026 Aug 16 12:45  sahib  added secret.txt (admin)
#3  ✓  2026 Aug 16 12:44  sahib  sealed 1 secret FiDCW+vMh6tc
#2  +  2026 Aug 16 12:44  sahib  added README.md (admin)
#1  ★  2026 Aug 16 12:44  sahib  initialized repo e98f1db4-afb

# finish the merge, this will seal all files:
$ git commit -am 'merge'
[main f7136ed] merge
```


### Caveats

- `git merge` can only be done locally. You will not be able to merge things on GitHub or any other forge (as the server has no access to secrets).
- If secrets have conflicts, the conflicts will be shown in the revealed paths with conflict markers.
- To merge, you need to be an admin user. This is required because any attempt of merging user changes needs admin access.
- `git` will always say the merge had conflicts - this is normal as the text printed by `sesam` explains.
- The `sesam.yml` files will always be resetted to the merged state. Any additional change will be lost.
- Merging without the git integration is not possible. Doing so will likely result in a repository state that does not survive `sesam verify`.
- If you have a secret that is binary in nature, we can't merge it with conflict markers. In this case we'll add a TODO `.theirs` version next to it and inform you.
- Secrets only the other side changed keep your plaintext until you finish: `sesam status` lists them as stale (S) and the finalize takes the incoming version. Edit one of them before finishing and it is diverged (!) - the finalize refuses, and you pick: `sesam reveal --all` takes the incoming version, `sesam seal --all` keeps yours.
- A rebase or cherry-pick uses the same machinery, but `git` runs no hook when they finish. Check `sesam status` afterwards: it names the operation and what is left to do. Secrets that lag behind show as stale there; `sesam reveal` refreshes them and `sesam seal` leaves them alone until you do.

# VERIFYING

Since `sesam` is a tool focused on security, we need to constantly check whether we have been compromised
and warn the user. There are several checks that are being run on commits, which will be explained in this chapter.

> **Warning**
>
> TL;DR:
>
> We recommend running `sesam verify --all` as part of your CI/CD pipeline.
> If it fails, you should fail the pipeline and let a human look over it.

### Audit Log

`sesam` is based on an audit log that keeps track of all
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

### Extended checks

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

# TEMPLATE SECRETS

> **Warning**
>
> This feature is not yet implemented.

So far we did not really talk about how *Secrets* actually look like. We just
assumed it was a file with a password in it or some x509 certificate. It is
rather common though that secrets are embedded in a larger structure.

On the other hand, quite often we have files that contain several secrets.
Let's assume we're building some service that is being fed environment variables from a file like this:

```bash
# SMTP variables:
export SMTP_USER=schorsch
export SMTP_PASSWORD="horsebatterystaple"

# Postgres variables:
export POSTGRES_USER=schorsch
export POSTGRES_PASSWORD="nevergonnagiveyouup"

# ...
```

> **Note**
>
> Just adding the whole file as secret is fine too. However, if you want to use
> features like Rotation then you need to split them up. Also,
> we believe splitting them up is a tidier since you can generate the output file
> via a template easily.

We can model such a case using **template secrets**:

```yaml
  - type: template
    path: secrets.env
    access: [deploy]
    template: |
      | # SMTP variables:
      | export SMTP_USER=schorsch
      | export SMTP_PASSWORD="<<smtp_password>>"
      |
      | # Postgres variables:
      | export POSTGRES_USER=schorsch
      | export POSTGRES_PASSWORD="<<postgres_password>>"
    secrets:
      # The keys are the same as for regular secrets, except:
      # - `path` is optional. If you leave it out, the password string is only stored in the rendered template.
      # - Each secret needs a "name" that is used for replacement above.
      # - They don't need to be on disk. Each secret can be read back by using the placeholder.
      # - The special "encoding" allows using secrets with all kind of characters in env files, json, ...
      - type: password
        name: smtp_password
        encoding: shell # json, url, ...
      # You can also include other files in here if you want to.
      - include: other.yml
```

# KEY ROTATION

> **Warning**
>
> This feature is not yet implemented.
>
> If you like, you can have a look at the plan to implement it [here](https://github.com/open-sesam/sesam/issues/40).


From our experience, the biggest security threat are not holes in the software
itself, but social factors. Colleagues leaving the company for example could
still have a local copy of all secrets. While you will 99% of the time leave
always on good terms you still have to consider those secrets as lost for the
other 1%.

> **Note**
>
> We use those terms:
>
> **rotate:** Replace a secret with a new secret of the same format.
> For example, an old password is replaced with a new one.
>
> **swap:** Replace a rotated secret at the place where it was used.
> For example, an ssh key that was rotated needs to be changed in *authorized_keys*.

In reality there is therefore no way to not rotate and swap secrets from time to time. We gave `sesam` therefore features that help with automating this tedious process.

# FREQUENTLY ASKED QUESTIONS

This page collects expected problems and questions that might arise.

### I cloned the repo but my secrets aren't there

A fresh clone does **not** reveal secrets on its own. The git integration lives
in the local git config and hooks, which are never part of a clone. After
cloning you have to install them once:

```bash
# Reveal the secrets explicitly:
sesam open
# Make sure it gets done automatically on the next checkout.
# If the repo already exists, this just re-installs the git-integration.
sesam init
```

> **Note**
>
> Config-based hooks need **git ≥ 2.54**. On older git the hooks are skipped and
> you have to run `sesam open` / `sesam seal` yourself. `sesam doctor` tells you
> what is and isn't wired up.

Only secrets you can actually decrypt are written out. The rest stay sealed
with no plaintext pendant. That is expected, not an error (see
Managing users).

### `sesam` keeps telling me "git-integration is not installed"

You are in a checkout where `sesam init` was never run - most often a fresh clone,
since the hooks and merge/diff drivers live in local git config, which is not part
of a clone. Run `sesam init` once to wire everything up (`sesam doctor` shows what
is missing).

If you deliberately want to work without the integration, silence the nudge for
this checkout:

```bash
touch .sesam/no-git-integration-warning
```

The marker is local and git-ignored, so it stays a per-checkout decision.

### `git diff` shows my secret in plaintext - is that a leak?

No. On `init`, `sesam` registers a `diff` textconv (`sesam show`) in
`.gitattributes`. When you run `git diff`, git pipes the encrypted object
through it so you see a **readable, local-only** diff. Nothing plaintext is
written to git - the committed blob under `.sesam/objects/` stays encrypted.

### `sesam` says the repository is locked

`sesam` takes a lock file (`.sesam.lock`, next to `.sesam`) so two processes
never write the state at once. If you see a lock error, another `sesam` command - or a git hook that calls one - is still running.
Wait for it, or raise the timeout:

```bash
sesam --lock-timeout 30s open
```

If a process was killed hard and left the lock behind, remove `.sesam.lock`
manually **after** making sure nothing else is running.

### I removed a user with `kill` but they can still read secrets

This is expected and it is sadly just a fact of life.
You have to consider all secrets they had access to as lost (see rotation).

`sesam kill` removes the user from the current state so they can no longer be
added as a recipient of *future* seals. It does **not** revoke access to what
they could already read:

1. Ciphertext they already pulled stays decryptable with their identity key,
   forever.
2. Past commits still contain those secrets encrypted to their old key.

> **kill is not revocation**
>
> To actually revoke access, follow `kill` with a rotation of every secret the
> user was able to read. Then re-deploy the secrets.

### `sesam verify` fails after a pull or merge

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
disable force-push at your forge (see Initialisation).

### `git merge` said "Automatic merge failed" but nothing looks broken

That is by design. When both branches changed the vault, `sesam` merges the audit
log for you and then stops the automatic merge commit so you can review the result
before it is written. If there are no leftover conflict markers, just finish the
merge the normal git way:

```bash
git commit
```

Please see the git integration page for more info.

### Do I have to resolve the encrypted files during a merge?

No. Encrypted objects and the audit log are merged by `sesam` in the background;
you never hand-resolve ciphertext. What you may have to resolve are the **revealed**
(plaintext) secrets: if both sides edited the same region of a file, `sesam` writes
normal git conflict markers into the revealed copy. Fix them like any other
conflict, then `git commit`.

git cannot see these markers (the tracked object is ciphertext, the plaintext is
git-ignored), so `sesam status` lists any file still carrying them - shown as `U`
/ `conflicted` - and the commit is refused until they are resolved.

### Can I merge several branches at once (`git merge A B`)?

No. `git`'s octopus strategy bypasses custom merge drivers, so `sesam` cannot merge
the vault that way. Merge one branch at a time.

### Who is allowed to merge branches?

Only admins. A merge re-signs the audit log and needs access to every affected
secret - both of which admins have. A non-admin merge aborts with `not an admin`;
ask an admin to run it.

### I ran `sesam uninstall` and now re-`init` fails with "init file check: … has uncommitted changes"

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

### How do I reveal secrets in CI/CD without a human?

Give the pipeline a dedicated machine identity (its own `age`/SSH key, told into
the groups it needs) and point `sesam` at it explicitly so nothing prompts on a
missing TTY:

```bash
sesam --identity /secure/ci-key.age verify --all
sesam --identity /secure/ci-key.age open
```

Run `sesam verify --all` **before** you deploy and let a non-zero exit stop the
pipeline. This is the integrity-vs-availability trade-off: a stronger check
means a broken or tampered repo fails the build instead of shipping stale or
malicious secrets. A scheduled verify job that alerts you before deploy time is
the best of both worlds.

> **Note**
>
> If `sesam` hangs or errors asking for a key in CI, it is running without a TTY
> and without a usable identity. Pass `--identity` (and, for a non-root `.sesam`,
> `--sesam-dir`) explicitly.

### I get an error about a root hash check

You might encounter one of these errors:

```text
● failed to verify audit log: reading signatures for root hash check: unexpected end of JSON input
● failed to verify audit log: root hash mismatch: log says abc, disk says xyz (try --verify-mode no-disk)
```

This means the audit log remembers a different state than what is on disk.

If you are sure that everything is fine (i.e. nobody swapped secrets when you were not on your watch)
then you can run:

```bash
sesam --verify-mode no-disk seal
```

This will re-seal existing revealed paths and add a new root hash to the audit log.
If it still is not fixed, an admin might have to run the same command (as you can only seal files that you have access to).

### I have entered my identity passphrase, but it's outdated

You can clear the cached passphrase in the system keyring:

```bash
sesam keyring clear
```

Next run will query the password again.

### `sesam` says the keyring is unavailable

On Linux, cached passphrases use the desktop Secret Service API. If no provider
is running, you may see errors from the system keyring such as `The name is not
activatable`. This does not mean the identity failed to unlock; it only means
`sesam` could not cache the passphrase for later.

Install or start a Secret Service provider such as GNOME Keyring, KWallet, or
another compatible daemon if you want passphrase caching. Otherwise you can
ignore it and enter the passphrase when asked.

### My shell wants to correct `sesam` to `.sesam`

i.e. you get something like this:

```bash
sesam ls
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

### Can I use `sesam` as password manager?

Yes! In fact I use it myself as an alternative to `pass`.
The `show` sub-command supports copying a secret to the clipboard. 

To get a list of selectable secrets, using [rofi](https://github.com/davatorium/rofi), would work like this:

```bash
export SESAM_ID=/path/to/your/id-key
export SESAM_DIR=/path/to/your/repo

# 1. List all secrets paths
# 2. Pipe them through rofi
# 3. rofi prints the selected one to stdout
# 4. copy it to clipboard via show

sesam ls --json | \
  jq -r  '.[].revealed_path' | \
  rofi -dmenu -p 'Secret name' | \
  xargs -n1 sesam show -c

```

Instead of `rofi` you could of course just use any other launcher or filter (e.g. `fzf`) of your choice.

# SEE ALSO

Handbook: <https://opensesam.org>

Source, issues and discussions: <https://github.com/open-sesam/sesam>
