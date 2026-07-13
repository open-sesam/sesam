# Installation

While this is in development you won't find this tool in package managers yet.
Once that will be available we will mention it here:

## Releases

Please check the [Releases tab](https://github.com/open-sesam/sesam/releases) for download options and release notes.

# Compiling from source

We use [mise](https://mise.en.dev/) to manage our development tools. All you
have to do to have exactly the same tools in exactly the right version is to
follow the [guide](https://mise.en.dev/getting-started.html). The TL;DR is:

```bash
$ git clone https://github.com/open-sesam/sesam.git
$ mise install
$ task # `sesam` will be in the top-level dir - copy it where you want to.
```

This is also the best way to start working on `sesam` if you want to open a PR.

Alternatively, if you already have `go` installed:

```bash
# This will not contain the build version really though:
$ go install github.com/open-sesam/sesam/cli@latest
```

# Docker

Every release is also available as docker image:

```bash
# Please swap `latest` with a release of your choice.
# Mount your repo & identity anywhere you want, you should specify them with command line options:
docker run -it -v ~/.ssh/id_rsa:/key -v .:/repo ghcr.io/open-sesam/sesam:latest -r /repo -i /key status
```


This can be useful for CI/CD pipelines or when you can't install `sesam` otherwise.

```admonish warn
Git integration will not be working with docker. Also storing passphrases will also not work.

You will also have to mount the sesam repo and your identity into the container with the `-v` option.

For real, interactive usage we very much recommend the regular version of `sesam`, the purpose of this image
is really to have just a minimal image for automation purposes.
```

### Signatures

We sign our releases with [ed25519 key](https://en.wikipedia.org/wiki/EdDSA), the private key is uploaded in encrypted form
as `.sesam` directory inside our this very repository. The public key is [here](TODO).

To verify the binary was indeed build by us, you can use your likely existing `openssl` installation:

```
```bash
$ openssl pkeyutl -verify -pubin -inkey public.pem -rawin -in ./sesam -sigfile signature.bin
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
