# sesam

Git-based secret management using age encryption with a cryptographically signed audit log.

## Commands

```bash
task test        # run tests (uses gotestsum)
task build       # build the sesam binary
task lint        # run golangci-lint
task coverage    # tests with coverage report (-coverpkg=./... captures testscript subprocess coverage too)
```

## Rules

- Assume users are senior developers. Make plans for them, challenge the ideas, review the code. This is no vibecoding project.
- Don't generate code, unless explicitly asked to do so.
- Do not wildly change existing comments. If you write new ones, keep them short and succinct.
- Do not write comments that just reference what was being prompted, describe what is actually being done.
- Ordering in source files: Types and interfaces go first, then implementations grouped by type.
- Testing: When adding tests, add them to a `xyz_test.go` where `xyz.go` is the file they belong to.
- Testing: There should be no `xyz_test.go` files with no `xyz.go`.
- Testing: use stretchr/require to assert things.
- Testing: use table driven tests where applicable.
- Testing: Use testscripts for e2e CLI based tests.

## Packages

- cli: CLI implementation. Should only contain env/flag parsing and visualization and calling high level API.
- repo: High level API for all operations do-able on the repository.
- core: Low level API doing one secret or user at a time and implementing the cryptographic primitives used here.
- config: Implementation for the config parsing, modification and marshalling.

## Documentation

Refer to the documentation under docs/ to see how the util should behave in general.

Especially the design document at docs/src/design.md should contain the current architecture.
If we change things written in there, alert the user and ask for explicit permission.

### Naming

- **tell** = add a user (`user.tell` operation, `DetailUserTell`)
- **kill** = remove a user (`user.kill` operation, `DetailUserKill`)
- The "admin" group is implicit - every secret and every `groupsToMap` call includes it automatically.

## Commit messages

Subjects follow Conventional Commits (`type: subject`) so `task changelog`
(via git-cliff, configured in `cliff.toml`) groups them correctly. Recognised
types: `feat`, `fix`, `security`, `perf`, `refactor`, `docs`, `test`, `chore`,
`ci`, `build`, `style`, `lint`. Mark breaking changes with `!` after the type
(e.g. `feat!: rename --repo to --sesam-dir`) or a `BREAKING CHANGE:` footer.
