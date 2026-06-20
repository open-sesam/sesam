# Managing secrets

## Adding a secret via CLI (imperative)

```admonish note
All secrets must be in the same folder as `sesam.yml` or below it.
We do not support adding secrets outside of the sesam repository.
```

If you have a secret at `path/to/secret`, then having it managed by `sesam` is only a matter of this command:

```bash
$ sesam add path/to/secret --group deploy
```

This will:

1. Record that this file is now managed by `sesam` by adding it to the audit log.
2. Encrypt the file and place it in `.sesam/objects`. This is what is being pushed in the end.

If you also like to have it committed, then just append a `--commit`.

## Adding a secret via config (declarative)

Adding secrets via CLI is nice for scripts. `sesam` also supports describing
the desired state in a declarative way via `sesam.yml`. If you executed the
above command you will notice the secret was added already to the config:

```yaml
secrets:
  - path: path/to/secret
    access: [deploy]
    description: Where it used, who owns it, Contact...
```

If you did not run the `add` command above, then you can also add the entry manually and then run:

```bash
$ sesam apply
```

This will automatically check what the state is in the repo and how it differs
from the state in the config. The changes are then resolved by adding/removing
secrets or adding/removing users.

## Adding multiple secrets

You can also add whole directories, if you need to:

```bash
$ tree dir/of/secrets
.
├── some_file
└── sub
    └── another_file
$ sesam add dir/of/secrets
$ tree dir/of/secrets
.
├── sesam.yml
├── some_file
└── sub
    ├── another_file
    └── sesam.yml
```

This will create a config hierarchy of `sesam.yml` files in the config:

```yaml
# Main sesam.yml:
config:
  secrets:
    - include: dir/of/secrets
```

```yaml
# dir/of/secrets sesam.yml:
config:
  secrets:
    - include: sub
    - path: some_file
```

```yaml
# sub sesam.yml:
config:
  secrets:
    - path: another_file
```

Once done you can also add descriptions to the files in the config or do more fine-tuning with the available [config keys](/config-ref.md).

```admonish note
If you ever create new files in the sub directories they do not automatically get added.
Instead you need to run `sesam add` again. This will also remove secrets that are not there anymore, if any.
In that sense, it works a bit like `git add`.
```

## Modifying secrets

Running `sesam add` will work too though, adding them is idempotent. It is
enough to run `sesam seal` if you only modified existing secrets though. This
simply encrypts ("seals") all known secrets by default, unless you pass `--no-pass`.

If you want to change the access groups of a user, then just pass a different set of `--group` flags.

## Removing secrets

If you have deleted files you can run this:

```bash
$ sesam rm  files/ dir/

```

```admonish warning
Please do not delete secrets just with `rm`. This will just remove the revealed file, but the
sealed file in `.sesam/` will still exist. On the next `sesam open` it will suddenly be back.
```


## Moving secrets

Probably not very surprising by now, but we have a `mv` command as well:

```bash
$ sesam mv old_name new_name

```


```admonish warning
The same warning as with `sesam rm` applies: Please do not just move the file
with `mv`. This will just move  the revealed file to a new name, but the sealed
file in `.sesam/` will still exist. On the next `sesam open` it will suddenly
be back with the old path.
```

## Listing secrets

```bash
$ sesam ls
├── README.sesam
└── dir
    └── of
        └── secrets
            ├── some_file
            └── sub
                └── another_file
```

You can also use the ``--json`` switch to print it in a more scriptable way.
