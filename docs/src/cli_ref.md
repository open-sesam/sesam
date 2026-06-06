# NAME

sesam - Manage encrypted secrets in git repositories

# SYNOPSIS

sesam

```
[--help|-h]
[--identity|-i|--id]=[value]
[--lock-timeout]=[value]
[--no-color]
[--quiet|-q]
[--sesam-dir|-r|--repo]=[value]
[--verbose|-v]
[--version]
```

**Usage**:

```
sesam [GLOBAL OPTIONS] [command [COMMAND OPTIONS]] [ARGUMENTS...]
```

# GLOBAL OPTIONS

**--help, -h**: show help

**--identity, -i, --id**="": Path to the age identity (can be given several times)

**--lock-timeout**="": Repository lock wait timeout (e.g. 5s, 30s, 2m) (default: 5s)

**--no-color**: Disable color always

**--quiet, -q**: Print less log output

**--sesam-dir, -r, --repo**="": Directory where .sesam lives (default: ".")

**--verbose, -v**: Print more log output

**--version**: Print the version and exit


# COMMANDS

## init

Initialize sesam in the current repository

**--help, -h**: show help

**--user**="": Initial admin user name (if not given, git config is used to guess)

## verify

Verify sesam signatures and encryption state

**--all**: Run all verifications

**--forge-check**: Verify the forge public keys did not change since adding users

**--help, -h**: show help

**--integrity**: Check file integrity on disk

**--json**: Print report as json

**--key-reuse**: Double-check that no key is re-used between users

**--truncate**: Verify the audit log was not truncated over history

## id

Identify the current user by age identity

**--help, -h**: show help

**--json**: Print as JSON

### clear-cache

Clear cached passprhases from the keyring

**--help, -h**: show help

## seal

Encrypt and sign changed secrets

**--clean**: Delete revealed secret files after successful seal

**--help, -h**: show help

## open, reveal

Decrypt all secrets available to the current user

**--help, -h**: show help

## add

Add a secret file or directory at `PATH`

**--group**="": Group assignment for the secret (repeatable) - 'admin' is implicit

**--help, -h**: show help

**--no-seal**: Do not run `sesam seal` after adding files - useful when batch adding

## rm

Remove a secret file or directory

**--help, -h**: show help

## tell

Add a person to a group and re-encrypt affected files

**--group**="": Group assignment (repeatable)

**--help, -h**: show help

**--recipient**="": Recipient key spec (e.g. github:alice) - can be given several times

**--user**="": User name to add

## kill

Remove a person from a group

**--help, -h**: show help

**--user**="": User name to remove

## show

Show objects managed by sesam

**--help, -h**: show help

## list, ls

List entities

**--help, -h**: show help

**--json**: Print output as JSON

### secrets

List known secrets and metadata

**--help, -h**: show help

**--json**: Print output as JSON

### users

List persons, groups, and access

**--help, -h**: show help

**--json**: Print output as JSON

## clean

Remove revealed plaintext and other untracked files from the sesam directory

**--aggressive**: Also delete other untracked files (similar to `git clean -fdx`)

**--dry-run**: Do not actually delete, just print what would be deleted

**--help, -h**: show help

