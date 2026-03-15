# Sesam Design

I want to develop an application in Go that manages secret files (think: passwords, ssh keys, certificates) used during development.
The target audience are developers.

## Hard Requirements

- Ease of use (commonly used technology liked YAML) / Safe to use (hard to accidentally push secrets)
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

## Ideas

### Security

Use 'age' as encrypt/decrypt tool. Advantages:

- We don't need to implement it ourself.
- Supports Hybrid Encryption really easily.
- Has support for Postquantum crypto even (when not using ssh keys and only age keys)
- Forges have a way to download user public keys as sort of key registry:
  - <https://github.com/USER>.<key>
  - <https://bitbucket.org/api/1.0/users/><accountname>/ssh-keys
  - <https://gitlab.com/USER.keys>
- Users could be specified as forge-username (e.g. github:sahib) or age public keys are transmitted separately.

### Configuration

- Yaml config hierarchy
  - sub directories can be included
  - Config specifies what secrets are there, what they do and how they can be rotated.
  - User/Groups define who has access to what.

- Separate recipients file defines who has access and groups:
  - Groups of users that are assigned to specific secrets (or wildcards of secrets)
  - Pre-defined "admin" group that can change the recipients file.
  - Only people in admin group are allowed to sign recipients file. Otherwise sesam errors out.

Secret types:

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
  - Something like: {{ pwgen zxcvbn=3 usage=3  }}
  - Or rather something that dynamically collects secrets from such files?
- AWS/Github/... keys. Needs per-service integration if possible.
- Custom
  - Generate: script
  - Exchange: script

### Misc

- Git pull as sanity check
- Work with whole dirs
- Parallel working should be possible -> only encrypt files that are changed.
- Signed commits when pushing something with sesam
- Use git attributes with smudge/clean filters to show git diffs locally.
  - Fully integrate into git (i.e. as "git sesam")
  - Filters could help having issues where dir content differs from what is checked out.
  - Auto configure git accordingly?
- Store encrypted files in .sesam, not alongside actual files.
- Implement command to view ownership of files easily.
- Note: Adding/Removing persons require re-encryption of all files.
- Make rotation command with multiple stages:

  - plan: Show which secrets are rotated, which are exchanged.
  - exec: Execute the plan above.
  - todo: keep track of manual work that could not be automated with command to mark items done.

- Logo idea: Sesame pod, but seeds replaced with small golden keys => Done
- README: Make clear that this is not vibe coded. Also mention that we think about rewriting in Rust after 1.0

TODO: What about same password used in several files? Is this one or two secret entries?
TODO: sesam should support several .sesam dirs per git repo

## YAML Example

See sesam.yml  for an example file

## Commands

Commands are subcommands of the sesam binary.
The binary can also be called as `git sesam`.

### init

- Create initial sesam.yml
- Make initial user admin-
- Set up .sesam/ dir
- Setup .gitignore file (ignore all but .sesam, sesam.yml)
- Setup .gitattributes file for smudge filters.
- Setup access to sesam as `git sesam`

### verify

- Check signature in sesam.yml
- For each secret:
  - Check that the configured access list is the same as the people that are able to decrypt the file.
  - This is to protect against an attacker that would attack himself to the access list.
  - Since the attacker is not able to decrypt files actually we can use that as a way to verify the
  - For every encrypted file we need to store a hash of the encrypted file, hash of the decrypted file and a signature.
  - This way we can detect if an attacker substituted a file with a version he controls.
- Verify is implicitly called after a pull, reveal or hide.
- Ideally this is also run as part of a CI pipeline.

Signature algorithm: Ed25519

### id

Identifies user based on ssh key.

### seal

Encrypt and sign files that were changed.

NOTE: Only seals the files that were changed by default.

### reveal

Reveals all secret files the user (defined by ssh-key) has access to.

NOTE: Only the files that you can access are visible in the git working dir.

### server

Allow fetching secrets via an API for runtime secret injection.
This should be compatible with the Vault HTTP API.

(Just a random idea to also go into the direction of server based tools)

### log

Show audit log:

- When where secrets changed by whom? Also includes the commit hash.
- When access list was changed by whom?
- When config was changed by whom?

Allow filtering by specific secrets or directories.

### undo

Check out an older secret by commit and restore it.

### modify

- add: Add a new file or folder to the config and encrypt it.
- rm:  Remove a file or folder from the config and remove it from disk.
- mv:  Like rm + add under new name.
- ls:  Print a list of secrets and metadata (optionally as JSON for parsing)

Commands only work when you are in the admin group.

- tell: Adds new person to a specified group and re-encrypt all affected files.
- kill: Removes a person to a specified group and
- list: List all persons that have acess along with their group (optionally as parse-able JSON)

### rotate

- plan: Show a plan of secrets that we can rotated and exchange.
- exec: Execute the previously made plan.
- todo: Show secrets...
  - ...that were rotated and exchanged (as "done" items)
  - ...that were rotated, but not exchanged.
  - ...that we did not know how to rotate and were not exchanged.

## Alternatives

- [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
- [git-secret](https://github.com/sobolevn/git-secret)
- [Keyringer](https://keyringer.pw/)
- [Transcrypt](https://github.com/elasticdog/transcrypt )
- [git-crypt](https://www.agwa.name/projects/git-crypt/)

None of them supports leveled access though.

There are more enterpris-y tools that run on server side:

- Infiscal
- Doppler
- Vault (hashicorp or ansible)
- ...
