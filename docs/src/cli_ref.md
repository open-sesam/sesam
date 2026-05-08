# sesam Command Reference

Manage encrypted secrets in git repositories

## Global Flags

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--identity`, `-i` |  | `SESAM_ID`, `SESAM_IDENTITY` | Path to the age identity (can be given several times) |
| `--config`, `-c` | `sesam.yml` | `SESAM_CONFIG` | Path to the sesam config file |
| `--sesam-dir`, `-r`, `--repo` | `.` | `SESAM_DIR` | Directory where .sesam lives |

## Commands

### `sesam init`

Initialize sesam in the current repository

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--user` `*` |  |  | Initial admin user name |
| `--use-root` |  |  | Initialize in the selected directory even when it already contains many files |

### `sesam verify`

Verify sesam signatures and encryption state

### `sesam id`

Identify the current user by age identity

### `sesam seal`

Encrypt and sign changed secrets

### `sesam reveal`

Decrypt all secrets available to the current user

### `sesam server`

Run the secret serving API

### `sesam log`

Show the audit log of secret changes

### `sesam undo`

Restore secrets from an earlier revision

### `sesam add`

Add a secret file or directory

### `sesam rm`

Remove a secret file or directory

### `sesam mv`

Move a secret to a different path

### `sesam list`

List known secrets and metadata

### `sesam apply`

Apply config differences to audit log and metadata

### `sesam tell`

Add a person to a group and re-encrypt affected files

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--user` `*` |  |  | User name to add |
| `--recipient` `*` |  |  | Recipient key spec (e.g. github:alice) - can be given several times |
| `--group` `*` |  |  | Group assignment (repeatable) |

### `sesam kill`

Remove a person from a group

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--user` `*` |  |  | User name to remove |

### `sesam list-users`

List persons, groups, and access

### `sesam show`

Show objects managed by sesam

### `sesam clean`

Remove revealed plaintext and other untracked files from the sesam directory

### `sesam rotate`

Plan and execute secret rotation

#### `sesam rotate plan`

Show the rotation and exchange plan

#### `sesam rotate exec`

Execute the planned rotation

#### `sesam rotate todo`

Show rotation tasks and follow-up status


> `*` - required flag
