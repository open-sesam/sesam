# Tips &amp; Tricks


## YAML anchors

If you want to re-use a part of your configuration, you can create a snippet:

```yaml
# Everything starting with "x-" on toplevel will be ignored.
x-default-access: &default-access
  access:
    - group1
    - group2
    - group3

# Use it: 
secrets:
  - path: foo.txt
    <<: *default-access
  - path: bar.txt
    <<: *default-access
```
  

For less often-used snippets it is sometimes useful to just reference another part directly:

```yaml
secrets:
  - path: foo.txt
    access: &default-access
      - group1
      - group2
      - group3
  - path: bar.txt
    <<: *default-access
```

Read up on [YAML anchors](https://en.wikipedia.org/wiki/YAML#Advanced_components) for more background.


## Git integration

Unlike most other tools, `sesam` integrates more with `git` to show you diffs and
record a consistent state on checkouts.

### Diffing

On `init`, we've setup [diff filters](https://git-scm.com/book/en/v2/Customizing-Git-Git-Attributes) via the `.gitattributes` file.
This means that `git` will pipe every change through `sesam reveal` before showing as diff.

`git diff HEAD^` should therefore just work out of the box and show you locally what was changed.

### Checkout

Something similar happens on `checkout` with smudge filters. When you check out an
older state with `git` we automatically reveal a fitting state. Files you do not have
access to are left out though.

### Audit log

`sesam` is based on a log that keeps track of all modifications made in the repository.
It can be useful to view it, if you're unsure on what happened:

```bash
$ sesam log
```

### Config linting

This will check your config for validity and report any issue:

```bash
$ sesam lint
```
