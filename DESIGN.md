# Sesam Design

Sesam is a tool for storing encrypted secrets (think: passwords, ssh keys,
certs, ...) and giving access to parts to it to a number of people. It is
supposed to be friendly for DevOps/GitOps and should be able to be used by
professional software teams during development.

## Hard Requirements

- Ease of use (commonly used technology liked YAML).
- Safe to use (hard to accidentally push secrets)
- Secure. Minimal information about the managed secrets should be leaked.
- Versioned, works with/wraps git ideally.
- Can easily rotate secrets (e.g. ssh keys, i.e. knows the type of common secrets and how they are generated)
- Can help exchanging secrets (e.g. also exchange the secret on the server)
- Supports storing metadata for each secret (e.g. "last rotated", "owner", "location of usage")
- Encryption and decryption should be fast.
- Usage needs to be scriptable (i.e. CLI program)
- Several users should have access via hybrid encryption. Only users added previously may access the raw files.
- Leveled Access. Some secrets should only be accessible by a certain subset of users that is pre-defined.
- Retain permissions (so ssh stops complaining after decrypt)

## Alternatives

There are roughly two concepts in this problem space:

1. Central tools: Store secrets in a central place, allow access to them via clients:

- Infiscal
- Doppler
- Hashicorp Vault
- Ansible Vault
- sops (can be central or decentral, it's a bit of an odd-ball)
- ...

2. Decentral tools: Often using a VCS, keep secrets in a:

- [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
- [git-secret](https://github.com/sobolevn/git-secret)
- [Keyringer](https://keyringer.pw/)
- [Transcrypt](https://github.com/elasticdog/transcrypt )
- [git-crypt](https://www.agwa.name/projects/git-crypt/)
- [agebox](<https://github.com/slok/agebox>)

### Why another tool?

- We like to have a decentralized tool that works well together with git.
- We need a tool that is easy to understand and reason about.
- None of the above decentralized tools support leveled access.
- Central tools are targeting really large organisations.

In general, our background is with `git-secret`. It was working kinda,
but had way too much bugs, pitfalls, inconveniences and missing features
to keep it for any longer.

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

## Commands

Commands are subcommands of the sesam binary.
The binary can also be called as `git sesam`.

### CLI Global options

Those options should be possible to specific for all commands (also via ENV variable):

- age identity path (default: `~/.config/sesam/key.txt`, or SSH key path, or plugin)
- config file path
- repo path
- verbose/quiet flags

### init

- Create initial sesam.yml
- Make initial user admin
- Set up .sesam/ dir (including .sesam/signkeys/)
- Generate Ed25519 signing keypair for the user, encrypt private key with user's age
  public key, store at `.sesam/signkeys/$user.age` (public key alongside in plaintext)
- Setup .gitignore file (ignore all but .sesam, sesam.yml)
- Setup .gitattributes file for smudge filters.
- Create git hooks to run verify before commit and potentially others
- Setup access to sesam as `git sesam`

### verify

- Verify the last audit log got not truncated.
- Parse the audit log.
  - Verify integrity via hashing and signatures.
  - Build a version of the repo according to the audit log.
  - Verify the constraints (e.g. only admins may add new users)
- Compare the audit log state to the actual state.
  - If there are no diffs: Good!
  - If there are diffs:
    - If we pulled from somebody: Alarm!
    - If we did local changes in sesam.yml - probably fine, but warn before push.
- For each secret:
  - Check that the configured access list is the same as the people that are able to decrypt the file.
  - Check the signature files for each secret. Signature and hash should be sound.
  - Signature files are themselves signed by the audit log.
- For each user:
  - Check which public keys belong to his configured identity. There should be at least one.
  - Check if the private key belongs to the signing public key in the config.
- Ideally this is also run as part of a CI pipeline.

### id

Identifies user based on their age identity (age key, SSH key, or plugin).
Just prints the user name and exits.

### seal

Encrypt and sign files that were changed.

NOTE: Only seals the files that were changed by default.

A `--push` option should be allowed to commit and push the secrets in one big step.

### reveal

Reveals all secret files the user (identified by age identity) has access to.

NOTE: Only the files that you can access are visible in the git working dir.

A `--pull` option should be allowed to pull in changes before reveal.

### server

Allow fetching secrets via an API for runtime secret injection.
This should be compatible with the Vault HTTP API.

(Just a random idea to also go into the direction of server based tools)

### log

Show audit log:

- When where secrets changed by whom? TODO: Include commit hash?
- When access list was changed by whom?
- When config was changed by whom?

Should also be able to show git version for a specific secret.

### config

#### diff

Show diffs between audit log and sesam.yml

#### apply

Apply the changes made to sesam.yml so they will appear in the audit log.

#### modify commands

- add: Add a new file or folder to the config and encrypt it.
- rm:  Remove a file or folder from the config and remove it from disk.
- mv:  Like rm + add under new name.
- ls:  Print a list of secrets and metadata (optionally as JSON for parsing)

Commands only work when you are in the admin group.

- tell: Adds new person to a specified group and re-encrypt all affected files.
- kill: Removes a person to a specified group and
- list: List all persons that have acess along with their group (optionally as parse-able JSON)

### undo

Check out an older secret by commit and restore it.

### rotate

- plan: Show a plan of secrets that we can rotated and exchange.
- exec: Execute the previously made plan.
- todo: Show secrets...
  - ...that were rotated and exchanged (as "done" items)
  - ...that were rotated, but not exchanged.
  - ...that we did not know how to rotate and were not exchanged.

## Implementation

### Libraries

- CLI: <https://cli.urfave.org/> - best CLI library.
- YAML: <https://github.com/goccy/go-yaml> - good error messages, well maintained.
  -> We need to work with the YAML ast directly to preserve comments!
- age: <https://github.com/FiloSottile/age> - encryption/decryption (including agessh for SSH key identities)
- ed25519: <https://pkg.go.dev/crypto/ed25519> - signing/verification of config and secrets
- renameio: <https://github.com/google/renameioc> - Atomic writes to disk
- zxcvbn: <https://pkg.go.dev/github.com/wneessen/zxcvbn-go> - Testing password strength
- password: <https://github.com/sethvargo/go-password> - Password generation
- git: <https://github.com/go-git/go-git> - git integration (like checking for remote changes)

### Modules

- CLI
- Config API
  - CRUD API user/groups
  - CRUD API secrets
  - Validation/Constraints:
    - Group names must be unique
    - User names must be unique
    - Group and user names may not overlap
- Repo API
  - init bootstrapping
  - git API
  - Sign/Verify
  - audit log
- Secret API
  - Encryption/Decryption
  - IO handling
  - Rotation/Exchange Plugin Architecture
  - Swap
- Identity:
  - Load age identity (native key, SSH key via agessh, or plugin)
  - Manage signing keypairs (generate, encrypt/store in `.sesam/signkeys/`, decrypt for signing)
  - Sign/Verify using Ed25519

### Extensions

Things like exchanging aws keys or generating github api keys should not be done by the main binary.
For security reasons, this binary should stay as small as possible with only the core features in it.
Everything else should be a downloadable plugin, which means:

- We need a plugin architecture - go supports this using plugin: <https://pkg.go.dev/plugin>
- Plugins should be downloadable using an URL and the main sesam tool should come with a list of officially tested plugins
  with their URL, correct hash and maybe even signature using a key pair of the maintainers.
- A specific sesam version points to specific plugin versions. The versions are curated to avoid sneaking in malicious plugins xz-style (aka supply chain attack).

Other things like a TUI should be a separate tool to keep attach surface small.
