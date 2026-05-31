# Installation

While this is in development, you can only clone the repo and run `task` to build the software.

```admonish note
You need to install [task](https://taskfile.dev/) for this.
```

# Changelog

The changelog is derived from our git history via [git-cliff](https://git-cliff.org/) and can be viewed at [CHANGELOG.md](https://raw.githubusercontent.com/open-sesam/sesam/refs/heads/main/CHANGELOG.md).
## Versioning schema

We use [semantic versioning](https://semver.org/):

```bash
$ sesam --version
0.1.2 [2fee38ca3] (2026-05-31) © 2026 Chris Pahl and contributors
```


### First stable version

```admonish warning
We will only guarantee stable interfaces (i.e. stable storage layout, stable API and backwards-compatible CLI) once we reach `1.0.0`.
```

Right now, we can't tell you yet when this `1.0.0` release will be. It might go fast, it might as-well take a long time.
This mostly depends on how `sesam` is used in the field and how much we feel we need to change it to keep up with reality.

However, after announcing the first test version to the world, we will think twice to change things around. We try to keep
the repository layout stable and also the CLI concepts should mostly stay the same.

## Releases

Please check the [Releases tab](https://github.com/open-sesam/sesam/releases) for download options and release notes.
