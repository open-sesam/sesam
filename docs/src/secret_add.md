# Adding secrets

## Adding a secret via CLI

```admonish note
All secrets must be in the same folder as `sesam.yml` or below it.
We do not support adding secrets outside of the sesam repository.
```

If you have a secret at `path/to/secret`, then having it managed by `sesam` is only a matter of this command:

```bash
$ sesam add --type password path/to/secret
```

## Adding a secret via Config

Adding secrets via CLI is nice for scripts. `sesam` also supports describing
the desired state in a declarative way via `sesam.yml`. If you executed the above command you will notice the secret was added already to the config:

```yaml
  - type: password
    path: path/to/secret
    description: Where it used, who owns it, Contact...
```

If you did not run the `add` command above, then you can also add the entry manually and then run:

```yaml
$ sesam apply
```

