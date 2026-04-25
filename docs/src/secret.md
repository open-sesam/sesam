# Managing secrets

## Adding a secret via CLI

```admonish note
All secrets must be in the same folder as `sesam.yml` or below it.
We do not support adding secrets outside of the sesam repository.
```

If you have a secret at `path/to/secret`, then having it managed by `sesam` is only a matter of this command:

```bash
$ sesam add path/to/secret
```

This will:

1. Record that this file is now managed by `sesam` by adding it to the audit log.
2. Encrypt the file and place it in `.sesam/objects`. This is what is being pushed in the end.

If you also like to have it committed, then just append a `--commit`.

## Adding a secret via Config

Adding secrets via CLI is nice for scripts. `sesam` also supports describing
the desired state in a declarative way via `sesam.yml`. If you executed the
above command you will notice the secret was added already to the config:

```yaml
config:
  secrets:
    - path: path/to/secret
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

## Modifiying secrets

Running `sesam add` will work too though, adding them is idempotent.
It is enough to run `sesam seal` if you only modified existing secrets though.
This simple encrypts ("seals") all known secrets. As per usual, it also has a ``--commit`` option.

## Removing secrets

If you have deleted files you can run this:

```bash
$ sesam add --deleted files/ dir/

```

```admonish note
The command above only helps you deleted files on disk and want to tell `sesam` now that
these files do not exist anymore. If you removed them from the config, then `sesam apply`
will not find them anymore.
```

## Listing secrets

```bash
$ sesam list secrets
├── README.sesam
└── dir
    └── of
        └── secrets
            ├── some_file
            └── sub
                └── another_file
```

You can also use the ``--json`` switch to print it in a more scriptable way.
