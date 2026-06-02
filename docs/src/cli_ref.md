# NAME

sesam - Manage encrypted secrets in git repositories

# SYNOPSIS

sesam

```
[--config|-c]=[value]
[--help|-h]
[--identity|-i]=[value]
[--lock-timeout]=[value]
[--sesam-dir|-r|--repo]=[value]
```

**Usage**:

```
sesam [GLOBAL OPTIONS] [command [COMMAND OPTIONS]] [ARGUMENTS...]
```

# GLOBAL OPTIONS

**--config, -c**="": Path to the sesam config file (default: "sesam.yml")

**--help, -h**: show help

**--identity, -i**="": Path to the age identity (can be given several times)

**--lock-timeout**="": Repository lock wait timeout (e.g. 5s, 30s, 2m) (default: 5s)

**--sesam-dir, -r, --repo**="": Directory where .sesam lives (default: ".")


# COMMANDS

## init

Initialize sesam in the current repository

**--help, -h**: show help

**--use-root**: Initialize in the selected directory even when it already contains many files

**--user**="": Initial admin user name

## verify

Verify sesam signatures and encryption state

**--help, -h**: show help

## id

Identify the current user by age identity

**--help, -h**: show help

## seal

Encrypt and sign changed secrets

**--clean**: Delete revealed secret files after successful seal

**--help, -h**: show help

## open, reveal

Decrypt all secrets available to the current user

**--help, -h**: show help

## add

Add a secret file or directory

**--group**="": Group assignment for the secret (repeatable)

**--help, -h**: show help

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

**--quiet**: Don't print files

