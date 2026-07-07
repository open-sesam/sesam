# Git integration

`sesam` integrates tightly with `git`.
This page gives you an overview what is being set-up for you by default.

## Diffing

On `init`, we setup [diff filters](https://git-scm.com/book/en/v2/Customizing-Git-Git-Attributes) via the `.gitattributes` file.
This means that `git` will pipe every change through `sesam show` before showing as diff.

Try for example committing your secrets and then run `git log -p` to see how secrets evolved over time.

Files you don't have access to will not be shown.

## Hooks

`git >= 2.54.0` [supports setting multiple hooks for a single
event](https://github.blog/open-source/git/highlights-from-git-2-54/#h-config-based-hooks)
in its config without requiring an external hook manager. We make use out if it
by registering the following hooks by default on `sesam init`. If you do not
wish to install them, then please pass `--install-hooks=false` to the `init`
command. You can also call `sesam hook install` or `sesam hook uninstall` at
any point later.

If you have an older version of `git` you can still hook up those by calling
`sesam hook pre-commit` or `sesam hook post-checkout` on the equally named hook.
Use either a hook manager of your choice or directly work with `.git/hooks`.

Keep in mind that hooks are always per-repo! They need to be set up freshly for
every new clone.

### `post-checkout`

When you check out an older state you likely want also the revealed files to have the content committed at this time.
This hook does the following:

- If we're checking out a branch, tag or other ref: We clean all revealed secrets and reveal freshly after `git` checked out the old state.
- If we're checking out a single file or directory: We reveal all secrets and re-seal the newly checked out secrets so they get added to the audit log.

```admonish note
This is not being called when running `git reset`. If you do this, you should probably run `sesam open` explicitly.
```

### `pre-commit`

When you commit you most likely want to make sure that all files you've edited in the worktree are sealed (i.e. `sesam status` shows nothing)
and no accidental tampering was done. This is done by this hook before every commit:

- Seal all files that have diffs with the current revealed secrets.
- Run `sesam verify --all`.

If errors happen the commit will be aborted and you can check if there is indeed something wrong.
If you decide that all is good you can still continue with `git commit --no-verify` (this skips running the hook temporarily).

## Merging branches

```admonish warning
This feature is not yet implemented.

See here for the [plan](https://github.com/open-sesam/sesam/issues/23).
```

Encrypted files appear as random bytes. Even the very same content can result in totally different ciphertext.
That's not something that makes `git merge` easy to use - all of those files will be recorded as merge conflicts if they
have been modified in different branches. Normal conflict resolution will not help in this case.

Luckily, we have the audit log. This log has been modified in both branches and can be traced to a common root.
Assuming a user has sufficient privileges (e.g. an admin) then those changes be replayed on top of each other and the merged
state can be revealed. If there are actual conflicts, then `sesam` will leave the conflict markers in the revealed secrets -
you can then continue to work out the conflicts like you are used from `git`. The next commit will again trigger the `pre-commit`
hook that will in turn make sure that all secrets are conflict marker free and sealed.

This is set-up for you via `.gitattributes` and the `sesam-merge-*` entries in your repo's `.git/config`.
