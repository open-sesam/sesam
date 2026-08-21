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

### `post-merge`

`git` does not run `post-checkout` after a merge, and a fast-forward merge (what
`git pull` usually is) runs no other hook either. Without this hook the revealed
files would keep the pre-merge content while the sealed objects moved on - and
the next `sesam seal` would write the stale plaintext back over what you pulled.

This hook reveals the secrets whose objects the merge changed. It stays out of
the way while conflicts are still unresolved in the index, so a merge you are
mid-way through resolving is never overwritten.

### `pre-commit`

When you commit you most likely want to make sure that all files you've edited in the worktree are sealed (i.e. `sesam status` shows nothing)
and no accidental tampering was done. This is done by this hook before every commit:

- Seal all files that have diffs with the current revealed secrets.
- Run `sesam verify --all`.

If errors happen the commit will be aborted and you can check if there is indeed something wrong.
If you decide that all is good you can still continue with `git commit --no-verify` (this skips running the hook temporarily).

## Merging branches

```admonish warn
As the other hooks, git >= 2.54 is required!
Merging without will inevtiably cause a broken repo state.
```

Encrypted files appear as random bytes. Even the very same content can result
in totally different ciphertext. That's not something that `git merge` can
handle - it needs to see the revealed files. Of course, only authorized users
have access to it.

Luckily, we have the audit log. This log has been modified in both branches and
can be traced to a common root. Assuming a user has sufficient privileges (i.e.
an admin) then those changes be replayed on top of each other and the merged
state can be revealed. If there are actual conflicts, then `sesam` will leave
the conflict markers in the revealed secrets - you can then continue to work
out the conflicts like you are used from `git`. The next commit will again
trigger the `pre-commit` hook that will in turn make sure that all secrets are
conflict marker free and sealed.

To merge two branches you go mostly the normal git flow:

1. `git merge <branch>`
2. Check the output of the `sesam` merge driver, clear conflicts if necessary.
3. `git commit`

One notable difference from the normal flow: There will be never an automatic
merge commit. To give you a chance to review the automated decision making done
by the merge driver we will always tell `git` that there were conflicts, so
don't be afraid of those messages.

What happens on the technical level:

- For every sealed secret we do a three-way merge of the revealed contents and write the merged content to the revealed path.
  If there are conflicts, the revealed path will contain conflict markers.
- The changes of the incoming audit log will be "rebased" (in the sense of re-done) onto our existing audit log.
  Conflicts are automatically resolved by heuristics, which are supposed to capture what a sensible user would usually do.
  (e.g. if a user was removed on our side, but updated on the other then the remove will win).
- The audit log will get a `merge` entry that will explain any conflicting decisions.
  If you want to see what secrets conflicted, then run `sesam status`.
- Added/changed/removed signing keys might still be present after the `git merge`. Those will be cleaned up by the `pre-commit` hook.
- The state on the disk might not fully reflect yet what the audit log says. An explicit seal is required, which is done automatically
  for you by the `pre-commit-hook` fired by `git commit`.
- If you forgot to clean a secret up (i.e. it still contains merge markers), the `pre-commit-hook` will stop you.

To understand better we should look at an example (slightly contrived) session:

```shell
$ mkdir merge-example && cd merge-example
# Create git & sesam & initial commit:
$ git init
$ sesam init
$ git add . && git commit -am 'base'

# on feature branch:
$ git checkout -b feature
$ echo hello > secret.txt
$ sesam add secret.txt --group admin
$ sesam tell --recipient github:Johnny2210 --group admin
$ git add . && git commit -am 'add secret.txt and Johnny'

# on main branch (derived from base):
$ git checkout main
$ echo world > secret.txt
$ sesam add secret.txt --group admin
$ sesam tell --recipient github:adelbables --group admin
$ git add . && git commit -am 'add secret.txt and Adel'

# Actual merge action:
$ git merge feature
sesam: automatically merging revealed file secret.txt; 1 conflict - please fix manually.
sesam: automatically merging revealed file README.md; no conflicts, but access to it changed on both sides
sesam: it will be sealed with the merged recipients when you commit
sesam: both sides changed the audit log.
sesam: the audit log was therefore semantically merged.
sesam:
sesam:
sesam: NOTE: git may tell you the operation failed below.
sesam:       this is only to give you a chance to review the repo state before continuing.
sesam:
sesam: resolve any conflicts mentioned above (if any), then check with `sesam status`.
sesam: finish this merge with `git commit`.
sesam: in case you don't have the git integration installed run `sesam hook pre-commit` directly.
sesam: if you're unsure what any of this means, you can also start over with `git merge --abort` and then `sesam reveal --all`
Auto-merging .sesam/audit/log.jsonl
Auto-merging .sesam/objects/README.md.sesam
Auto-merging .sesam/objects/secret.txt.sesam
CONFLICT (add/add): Merge conflict in .sesam/objects/secret.txt.sesam
Auto-merging sesam.yml
Automatic merge failed; fix conflicts and then commit the result.


# You will see merge 
$ cat secret.txt
<<<<<<< ours/secret.txt
world
||||||| origin/secret.txt
=======
hello
>>>>>>> theirs/secret.txt

$ sesam status
.
├─ M README.md (admin)
╰─ U secret.txt (admin)
  1 conflicted · 1 out of sync

a merge is in progress.
  resolve the conflicted (U) secrets above, then run `sesam seal`
  and finish with `git commit`
  or start over with `git merge --abort` followed by `sesam reveal --all`

# Do a content merge:
$ echo 'hello world' > secret.txt

$ sesam status
.
├─ M README.md (admin)
╰─ M secret.txt (admin)
  2 out of sync

a merge is in progress.
  resolve the conflicted (U) secrets above, then run `sesam seal`
  and finish with `git commit`
  or start over with `git merge --abort` followed by `sesam reveal --all`

# Audit log was automatically merged:
$ sesam log
#9  ⋈  2026 Aug 16 12:46  sahib  merged audit log (1 applied, 3 dropped)
#8  +  2026 Aug 16 12:44  sahib  told Johnny2210 into admin
#7  ✓  2026 Aug 16 12:45  sahib  sealed 2 secrets FiDFG71BQ9PX
#6  +  2026 Aug 16 12:45  sahib  told adelbables into admin
#5  ✓  2026 Aug 16 12:45  sahib  sealed 2 secrets FiCe0k67WVO6
#4  +  2026 Aug 16 12:45  sahib  added secret.txt (admin)
#3  ✓  2026 Aug 16 12:44  sahib  sealed 1 secret FiDCW+vMh6tc
#2  +  2026 Aug 16 12:44  sahib  added README.md (admin)
#1  ★  2026 Aug 16 12:44  sahib  initialized repo e98f1db4-afb

# finish the merge, this will seal all files:
$ git commit -am 'merge'
[main f7136ed] merge
```


### Caveats

- `git merge` can only be done locally. You will not be able to merge things on GitHub or any other forge (as the server has no access to secrets).
- If secrets have conflicts, the conflicts will be shown in the revealed paths with conflict markers.
- To merge, you need to be an admin user. This is required because any attempt of merging user changes needs admin access.
- `git` will always say the merge had conflicts - this is normal as the text printed by `sesam` explains.
- The `sesam.yml` files will always be resetted to the merged state. Any additional change will be lost.
- Merging without the git integration is not possible. Doing so will likely result in a repository state that does not survive `sesam verify`.
- If you have a secret that is binary in nature, we can't merge it with conflict markers. In this case we'll add a TODO `.theirs` version next to it and inform you.
- A rebase or cherry-pick uses the same machinery, but `git` runs no hook when they finish. Check `sesam status` afterwards: it names the operation and what is left to do.

### Internal flow

This is purely informal, for normal usage you do not need to understand this.
This is the set-up for you via `.gitattributes` and the `sesam-merge-*` entries in your repo's `.git/config`:

```
                                ┌────────────────────────┐   write conflict                                                                                                 
                           ┌────► sesam merge secret     ├──►if required   ─────┐                                                                                           
                           │    └────────────────────────┘                      │                                                                                           
                           │                                                    │                                                                                           
 ┌─────────────────────┐   │    ┌────────────────────────┐   semantic merge     │ ┌──────────────────┐                     ┌────────────────┐      ┌────────────────┐       
 │ git merge <theirs>  ┼───┼────► sesam merge audit      ├──►without user   ────┼►│pre-merge-commit  ├───►merge review────►│ git commit[...]├─────►│ pre-commit-hook│       
 └─────────────────────┘   │    └────────────────────────┘                      │ └──────────────────┘    by user          └────────────────┘      └────────────────┘       
                           │                                                    │  (fail on purpose)                                                                        
                           │    ┌────────────────────────┐                      │                                                                                           
                           └────► (take <ours> signkeys) ├──►signkeys are ──────┘                                                                                           
                                └────────────────────────┘   merged later                                                                                                   
```
