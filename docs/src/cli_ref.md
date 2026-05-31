# sesam Command Reference

Manage encrypted secrets in git repositories

## Global Flags

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--identity`, `-i` |  | `SESAM_ID`, `SESAM_IDENTITY` | Path to the age identity (can be given several times) |
| `--config`, `-c` | `sesam.yml` | `SESAM_CONFIG` | Path to the sesam config file |
| `--sesam-dir`, `-r`, `--repo` | `.` | `SESAM_DIR` | Directory where .sesam lives |
| `--lock-timeout` | `5s` | `SESAM_LOCK_TIMEOUT` | Repository lock wait timeout (e.g. 5s, 30s, 2m) |

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

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--clean` |  |  | Delete revealed secret files after successful seal |

### `sesam open`

Decrypt all secrets available to the current user

### `sesam add`

Add a secret file or directory

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--group` `*` |  |  | Group assignment for the secret (repeatable) |

### `sesam rm`

Remove a secret file or directory

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

### `sesam show`

Show objects managed by sesam

### `sesam list`

List entities

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--json` |  |  | Print output as JSON |

#### `sesam list secrets`

List known secrets and metadata

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--json` |  |  | Print output as JSON |

#### `sesam list users`

List persons, groups, and access

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--json` |  |  | Print output as JSON |

### `sesam clean`

Remove revealed plaintext and other untracked files from the sesam directory

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--aggressive` |  |  | Also delete other untracked files (similar to `git clean -fdx`) |
| `--dry-run` |  |  | Do not actually delete, just print what would be deleted |
| `--quiet` |  |  | Don't print files |


> `*` - required flag
