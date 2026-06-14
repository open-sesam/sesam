# NAME

sesam - Manage encrypted secrets in git repositories

# SYNOPSIS

sesam

```
[--help|-h]
[--identity|-i]=[value]
[--lock-timeout]=[value]
[--no-color]
[--quiet|-q]
[--sesam-dir|-r|--repo]=[value]
[--verbose|-v]
[--verify-mode]=[value]
[--version]
```

**Usage**:

```
sesam [GLOBAL OPTIONS] [command [COMMAND OPTIONS]] [ARGUMENTS...]
```

# GLOBAL OPTIONS

**--help, -h**: show help

**--identity, -i**="": Path to the age identity (can be given several times)

**--lock-timeout**="": Repository lock wait timeout (e.g. 5s, 30s, 2m) (default: 5s)

**--no-color**: Disable color always

**--quiet, -q**: Print less log output

**--sesam-dir, -r, --repo**="": Directory where .sesam lives (default: ".")

**--verbose, -v**: Print more log output

**--verify-mode**="": Adjust how strong or weak the disk state is verified ('all', or 'no-disk') (default: "all")

**--version**: Print the version and exit


# COMMANDS

## init

Initialize sesam in the current repository

**--help, -h**: show help

**--user**="": Initial admin user name (if not given, git config is used to guess)

## deinit

Remove all traces of sesam

**--help, -h**: show help

## verify

Verify sesam signatures and encryption state

**--all**: Run all verifications

**--forge-check**: Verify the forge public keys did not change since adding users

**--help, -h**: show help

**--integrity**: Check file integrity on disk

**--json**: Print output as JSON

**--key-reuse**: Double-check that no key is re-used between users

**--truncate**: Verify the audit log was not truncated over history

## clean

Remove revealed plaintext and other untracked files from the sesam directory

**--aggressive**: Also delete other untracked files (similar to `git clean -fdx`)

**--dry-run**: Do not actually delete, just print what would be deleted

**--help, -h**: show help

## doctor

Check sesam installation for possible problems

**--help, -h**: show help

## add

Add a secret file or directory at `PATH`

**--group**="": Group assignment for the secret (repeatable) - 'admin' is implicit

**--help, -h**: show help

**--no-seal**: Do not run `sesam seal` afterwards - useful when batching

## rm

Remove a secret file or directory

**--help, -h**: show help

## mv

Move a secret file or directory to a new name

**--help, -h**: show help

## edit

Edit an secret and immeediately seal it afterwards

**--help, -h**: show help

## seal

Encrypt and sign changed secrets

**--clean**: Delete revealed secret files after successful seal

**--help, -h**: show help

## open, reveal

Decrypt all secrets available to the current user

**--help, -h**: show help

## status

Show secrets that are not sealed yet

**--all, -a**: Also show in-sync secrets and unmanaged files (hidden by default)

**--diff, -d**: Also show the actual diff

**--help, -h**: show help

**--json**: Print output as JSON

**--sort-by-state, -s**: Sort by state instead of path

## show

Show objects managed by sesam

**--help, -h**: show help

## ls, list-secrets

List known secrets and metadata

**--help, -h**: show help

**--json**: Print output as JSON

## rotate

Plan and execute secret rotation

**--help, -h**: show help

## tell

Add a person to a group and re-encrypt affected files

**--group**="": Group assignment (repeatable)

**--help, -h**: show help

**--no-seal**: Do not run `sesam seal` afterwards - useful when batching

**--recipient**="": Recipient key spec (e.g. github:alice) - can be given several times

**--user**="": User name to add

## kill

Remove a person from a group

**--help, -h**: show help

**--no-seal**: Do not run `sesam seal` afterwards - useful when batching

**--user**="": User name to remove

## user, u

User management commands

**--help, -h**: show help

### list

List persons, groups, and access

**--help, -h**: show help

**--json**: Print output as JSON

### change-groups

Change the groups a user is in

**--group**="": Group assignment for the secret (repeatable) - 'admin' is implicit

**--help, -h**: show help

**--no-seal**: Do not run `sesam seal` afterwards - useful when batching

**--user**="": Which user should be changed

### rename

Give a user a different name

**--help, -h**: show help

## config

Config management commands

**--help, -h**: show help

### apply

Apply config differences to audit log and metadata

**--help, -h**: show help

### diff

Show the diff between config and actual state

**--help, -h**: show help

### get

Get specific config keys

**--help, -h**: show help

### set

Set specific config keys

**--help, -h**: show help

## apply

alias for `sesam config apply`

**--help, -h**: show help

## id

Identify the current user by age identity

**--help, -h**: show help

**--json**: Print output as JSON

## keyring

Keyring utils

**--help, -h**: show help

### clear

Clear cached passphrases from the keyring

**--help, -h**: show help

## log

Show the audit log of secret changes

**--help, -h**: show help

**--json**: Print output as JSON

