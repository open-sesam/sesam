# Installation

While this is in development you won't find sesam in your package managers yet.
Once that will be available we will mention it here.
For now use the release binaries from GitHub, Docker image, go install or build form source.

## Releases

Please check the [Releases tab](https://github.com/open-sesam/sesam/releases) for download options and release notes.
We currently publish archives for Linux and macOS on amd64 and arm64.


```admonish note
You should then copy the `sesam` binary manually to a directory listed in your PATH (e.g. `/usr/local/bin` or `~/bin/`).

This is required so that `git` can find `sesam` - it will call `sesam` as subprocess.
```

### Signatures

We sign our releases with an [ed25519 key](https://en.wikipedia.org/wiki/EdDSA),
the private key is uploaded in encrypted form as `.sesam` directory inside our
this very repository. Here's how you verify the validity of the signature when
downloading:

#### Grab the `allowed_signers.txt`

This file contains the public keys of the people that are allowed to sign git tags and artifacts:

```bash
curl -LO https://raw.githubusercontent.com/open-sesam/sesam/main/allowed_signers.txt
```

For this step, only the releaser key is important.

#### Verify the signature

1. Download the `checksums.txt` of that specific release.
2. Download the `checksums.txt.sig` of that specific release.
3. Download the right `.tar.gz` for your platform.

```bash
# Note: The signature is build over the list of checksums.
ssh-keygen -Y verify -f allowed_signers.txt -I release@sesam -n sesam-release -s checksums.txt.sig < checksums.txt
```

#### Check that the checksums are actually correct

Now that we know the checksums are authentic, we just need to make sure the
archives match them.

```bash
sha256sum --ignore-missing -c checksums.txt
```

If that prints `OK` you're fine!

----

#### Automate verification

If you understood the previous steps you can also run this command in one go:

```bash

# This is convenience for the three steps above - you should of course verify that script first.
curl -LO https://raw.githubusercontent.com/open-sesam/sesam/main/scripts/verify-release.sh
bash verify-release.sh sesam_0.1.2_linux_amd64.tar.gz
```

## Compiling From Source

We use [mise](https://mise.jdx.dev/) to manage our development tools. All you
have to do to have exactly the same tools in exactly the right version is to
follow the [guide](https://mise.en.dev/getting-started.html). The TL;DR is:

```bash
git clone https://github.com/open-sesam/sesam.git
cd sesam
mise trust
mise install
task # builds the default release-style Linux amd64 binary in the top-level dir.
cp sesam /usr/local/bin/  # or wherever you want to install it.
```

This is also the best way to start working on `sesam` if you want to open a PR.

Alternatively, if you already have `go` installed:

```bash
# Replace @latest with a git tag of your choice.
# This will not contain the build version really though!
go install opensesam.org/sesam@latest
```

## Docker

Every release is also available as a Docker image:

```bash
# Please swap `latest` with a release of your choice.
# Mount your repo & identity anywhere you want, you should specify them with command line options:
docker run -it -v ~/.ssh/id_rsa:/key -v .:/repo ghcr.io/open-sesam/sesam:latest -r /repo -i /key status
```

This can be useful for CI/CD pipelines or when you can't install `sesam` otherwise.

```admonish warn
Git integration will not be working with docker. Also storing passphrases will not work.

You will also have to mount the sesam repo and your identity into the container with the `-v` option.

For real, interactive usage we very much recommend the regular version of `sesam`, the purpose of this image
is really to have just a minimal image for automation purposes.
```

## Changelog

The changelog is derived from our git history via [git-cliff](https://git-cliff.org/) and can be viewed at [CHANGELOG.md](https://raw.githubusercontent.com/open-sesam/sesam/refs/heads/main/CHANGELOG.md).

## Versioning Scheme

We use [semantic versioning](https://semver.org/):

```bash
sesam --version
0.1.2 [2fee38ca3] (2026-05-31) © 2026 Chris Pahl and contributors
```

### First stable version

```admonish warning
We will only guarantee stable interfaces (i.e. stable storage layout, stable API and backwards-compatible CLI) once we reach `1.0.0`.
```

Right now, we can't tell you yet when this `1.0.0` release will be. It might go fast, or it might take a long time.
This mostly depends on how `sesam` is used in the field and how much we feel we need to change it to keep up with reality.

However, after announcing the first test version to the world, we will think twice to change things around. We try to keep
the repository layout stable and also the CLI concepts should mostly stay the same.
