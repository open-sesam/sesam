# sesam: A clever git secrets manager 

[![CI](https://github.com/open-sesam/sesam/actions/workflows/ci.yml/badge.svg)](https://github.com/open-sesam/sesam/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mdBook-blue)](https://opensesam.org/)
[![Go Reference](https://pkg.go.dev/badge/github.com/open-sesam/sesam.svg)](https://pkg.go.dev/github.com/open-sesam/sesam)
[![Latest tag](https://img.shields.io/github/v/tag/open-sesam/sesam)](https://github.com/open-sesam/sesam/tags)
[![Maintenance](https://img.shields.io/maintenance/yes/2026)](https://github.com/open-sesam/sesam/commits/main)
[![License: GPL v3](https://img.shields.io/github/license/open-sesam/sesam)](LICENSE)

![Sesam](sesam.png)

<p align="center"><b>Encrypted, multi-user secrets that live in your git repo — and nowhere else.</b></p>

<p align="center">
  <a href="https://opensesam.org/">Documentation</a> ·
  <a href="https://opensesam.org/installation.html">Installation</a> ·
  <a href="https://opensesam.org/alternatives.html">Alternatives</a> ·
  <a href="https://github.com/open-sesam/sesam/blob/main/CHANGELOG.md">Changelog</a>
</p>

> [!WARNING]  
> This is still beta software. It somewhat works, but it may change.
> There is no guarantee before v1.0 that APIs and storage will not change.
> Use at your own risk for now.

# What is it?

`sesam` is a tool to manage `secret` (as in encrypted) files in `git`, so that
no unauthorised persons have access to them. Other than a password manager,
which targets a single user, it is targeting teams that need access to a set of
secrets. It is more capable [than existing decentralized secret
managers](https://opensesam.org/alternatives.html).

<a href="https://asciinema.org/a/1251104" target="_blank"><img src="https://asciinema.org/a/1251104.svg" /></a>

## Features

- Modern, multi-user cryptography with [age](https://github.com/FiloSottile/age)
- Allows giving layered access to secrets.
- Well integrated with `git` (diff, checkout)
- Decentralized like `git` - you get versioning and hosting for free.
- Wide range of verifications thanks to audit log.
- Integration with popular forges like GitHub.
- Ergonomic, easy-to-understand CLI.
- Imperative (CLI) and declarative (Config) workflows are supported.
- Simple modern deployment with a static binary.
- Highly scriptable and even usable as Go library.

## Planned features

- Rotation and exchange of secrets.
- Better support for env-file based workflows.
- Allow merging of git branches with secrets in them.
- Possibly also a TUI.

# Quickstart Links

- [Documentation](https://opensesam.org/)
- [Installation](https://opensesam.org/installation.html)
- [Contributing](https://github.com/open-sesam/sesam/blob/main/CONTRIBUTING.md)
- [Changelog](https://github.com/open-sesam/sesam/blob/main/CHANGELOG.md)
- [Releases](https://github.com/open-sesam/sesam/releases)
- [License](https://github.com/open-sesam/sesam/blob/main/LICENSE)
- [Alternatives](https://opensesam.org/alternatives.html)
- [Design](https://opensesam.org/design.html)

# AI Disclaimer

Those are weird times for software developers, therefore we feel obliged to note down how `sesam` is being developed.
We use AI-based assistants so far for:

  - Reviewing / Auditing.
  - Ideation / Design feedback.
  - Building test suites.
  - Occasional clearly scoped code change. 

The majority of the code is still hand-written to make sure we don't lose touch
to what we build. To be clear: **This is not a vibe-coded project.** The design
was done by an experienced software engineer the old-fashioned way.
