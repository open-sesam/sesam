# Contributor guidelines

This document is for you if you like to work on `sesam` - i.e. add features or fix bugs.

> [!IMPORTANT]  
> **Keep in mind that `sesam` is a security focused tool that might have access
> to critical secrets. We have to avoid supply chain attacks and other leaks as best we can.
> Please don't take it personal if we are very thorough while checking your contributions therefore.**

## Issues

We use the [GitHub Issue](https://github.com/open-sesam/sesam/issues) tracker.
Maybe the fix/feature or question is already there?

## Commits

We use [KeepAChangelog](https://keepachangelog.com/en/1.0.0/) and
[git-cliff](https://git-cliff.org/) to generate our changelogs. To make that
work you should do your commits via the [Conventional
Commits](https://www.conventionalcommits.org/) format. Thank you for sticking to that!

**If you make breaking changes:** Use an exclamation mark (`!`) to indicate a commit breaks backwards compatibility (e.g.: `feat!: delete show command`).

## PRs

- Please check if a similar PR already exists.
- Create a PR from a branch named `feat/...`, `fix/...` (same as in *ConventionalCommits*)
- Make sure CI runs through (local `task test` and `task lint`).
- Assign two of [*@sahib*](https://github.com/sahib), [*@adelbables*](https://github.com/adelbables), [*@Johnny2210*](https://github.com/Johnny2210), [*@moeux*](https://github.com/moeux) once you are ready for review.
- Wait for the review and work with us to get it merged.

Unsure if you should do a PR or unsure on implementation details?
Feel free to write a Issue first.

## AI usage

- We use AI-based assistants ourselves for reviewing, ideation, tests and the occasional clearly scoped code change. The majority code is still hand-written to make sure we don't loose touch.
- However, we will reject a PR if we feel it is completely vibe-coded and beyond a certain size. AIs are too good at creating correct-looking but utterly-broken code.
- Please do not automate communication via LLMs. `sesam` is a tool from humans for humans.
