# Template secrets

So far we did not really talk about how *Secrets* actually look like. We just
assumed it was a file with a password in it or some x509 certificate. It is
rather common though that secrets are embedded in a larger structure.

On the other hand, quite often we have files that contain several secrets.
Let's assume we're building some service that is being fed environment variables from a file like this:

```bash
# SMTP variables:
export SMTP_USER=schorsch
export SMTP_PASSWORD="horsebatterystaple"

# Postgres variables:
export POSTGRES_USER=schorsch
export POSTGRES_PASSWORD="nevergonnagiveyouup"

# ...
```

```admonish note
Just adding the whole file as secret is fine too. However, if you want to use
features like [Rotation](./rotation.md) then you need to split them up. Also,
we believe splitting them up is a tidier since you can generate the output file
via a template easily.
```

We can model such a case using **template secrets**:

```yaml
  - type: template
    path: secrets.env
    access: [deploy]
    template: |
      | # SMTP variables:
      | export SMTP_USER=schorsch
      | export SMTP_PASSWORD="<<smtp_password>>"
      |
      | # Postgres variables:
      | export POSTGRES_USER=schorsch
      | export POSTGRES_PASSWORD="<<postgres_password>>"
    secrets:
      # The keys are the same as for regular secrets, except:
      # - `path` is optional. If you leave it out, the password string is only stored in the rendered template.
      # - Each secret needs a "name" that is used for replacement above.
      # - They don't need to be on disk. Each secret can be read back by using the placeholder.
      # - The special "encoding" allows using secrets with all kind of characters in env files, json, ...
      - type: password
        name: smtp_password
        encoding: shell # json, url, ...
      # You can also include other files in here if you want to.
      - include: other.yml
```

