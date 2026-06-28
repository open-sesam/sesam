# Git integration

`sesam` integrates quite a bit with `git`.
This page gives you an overview what is being set-up for you.

## Diffing

On `init`, we setup [diff filters](https://git-scm.com/book/en/v2/Customizing-Git-Git-Attributes) via the `.gitattributes` file.
This means that `git` will pipe every change through `sesam show` before showing as diff.

Try for example committing your secrets and then run `git log -p` to see how secrets evolved over time.

## Checkout

```admonish warn
This feature is not yet implemented.

See here for the [plan](https://github.com/open-sesam/sesam/issues/33).
```

When you check out an older state you likely want also the revealed files to have the content committed at this time.
For this we register `post-checkout` hook that will make sure that all files you can reveal are revealed and all other
files are cleaned.

## Pre commit verify

```admonish warn
This feature is not yet implemented.

See here for the [plan](https://github.com/open-sesam/sesam/issues/33).
```

By default, we also register a pre-commit hook that will run `sesam verify --all` to double check that there are no
issues (from forgetting to have sealed files to integrity issues with what you are committing).

## Merging branches

```admonish warn
This feature is not yet implemented.

See here for the [plan](https://github.com/open-sesam/sesam/issues/23).
```

Encrypted files are by definiton random bytes. Even the very same content can result in totally different ciphertext.
That's not something that makes `git merge` easy to use - all of those files will be recorded as merge conflicts if they
have been modified in different branches. Normal conflict resolution will not help in this case.

Luckily, we have the audit log. This log has been modified in both branches and can be traced to a common root.
Assuming a user has sufficient privileges (e.g. an admin) then those changes be replayed on top of each other and the merged
state can be revealed. If there are actual conflicts, then `sesam` will leave the conflict markers in the revealed secrets -
you can then continue to work completely normal.

This is set-up for you via `.gitattributes` and the `sesam-merge` entry in your repo's `.git/config`.
