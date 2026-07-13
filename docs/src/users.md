# Managing users

## Managing users via config

As mentioned during [Initialisation](/init.md) there is always at least one admin user.
At the time you created your repo, you would see something like this in your config:

```yaml
config:
  users:
    - name: bob
      desc: Bob the Builder
      pub: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6VzKY/HxjYdIjBnRi6Nq7/0ydsKpX3uk1gu/ywUDJj
  groups:
    admin:
      - bob
```

As you can see, `bob` is an admin. Let's assume we are building a cloud backend
in a team and want to give some users the access to the required secrets for
deployment. We can do so by adding some more users and a new group:

```diff
   users:
     - name: bob
       desc: Bob the Builder
       pub: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6VzKY/HxjYdIjBnRi6Nq7/0ydsKpX3uk1gu/ywUDJj
+    - name: alice
+      desc: Mrs. Wonderland
+      pub: github:alice
+    - name: peter
+      desc: Peter Lustig
+      pub: file://keys/peter.txt
   groups:
     admin:
       - bob
+    deployment:
+      - alice
+      - peter
```

We've used two new ways to fetch the keys:

* `github:alice` will use all configured public keys of the GitHub user
`alice` (actually it's just the `https://github.com/alice.keys`). Many forges support API to fetch this information. You can also use
`gitlab:` or `codeberg:`. This makes adding new users really easy, as you most
likely already know the user name of your peer on your favorite forge.
The public key will be fetched only once initially and the result is cached. Apart from the first time there is no online access required therefore.
* Peter on the other hand might not have an forge account. Maybe he also has an awful long RSA key that you don't want to put in the config verbatim. In this case you can just create a file in the repo and add it there. We recommend adding an exception to `.gitignore` if you want to push those public keys.
- The key of `bob` was deferred from the identity used during init. If you use the same public key for (e.g.) your GitHub account you can also write something like `github:bob` there.


Once we've changed the config we can this command, which should be familiar by now. This will then adjust the repository state accordingly:

```bash
$ sesam apply
- added user `alice`
- added user `peter`
```

Changing groups later works the same way.

```admonish note
Only admins may add/change other user and groups. If you're not an admin (determined by your identity) you will get an error.
```

----

Adding users and groups does not automatically give them access to secrets.
We have to specify for each secret which groups have access to them (Reminder: the `admin` group has access always). Let's add them:

```diff
secrets:
  - path: some_password.txt
+   access:
+   - deployment
```

If you run `sesam apply` again, other users will have access. You have to commit (if you did not use ``--commit`` of course) and push it via git, of course. Then the others can pull the changes:


```bash
# on the laptop of alice:
$ git pull
$ sesam open
```

## Managing users via CLI

You can have the same effect without editing configs:

```bash
# Add users like above:
$ sesam tell --user alice --recipient "github:alice"
$ sesam tell --user peter --recipient "file://keys/peter.txt"
# --access can be given several times:
$ sesam add some_password.txt --access deploy --access ops
```

`sesam tell` also works on a user that already exists: it changes their groups
(`--group` replaces the set, `--group-add`/`-G` adds to it) and adds any
`--recipient` you pass. For an existing user both are optional, but you have to
give at least one. Creating a brand-new user requires a `--recipient`; groups
are optional there too.

```bash
# alice already exists: set her groups to just "ops"
$ sesam tell --user alice --group ops
# ...and additionally put her in "deploy" without dropping "ops"
$ sesam tell --user alice --group-add deploy
# register a second device key for her without touching her groups
$ sesam tell --user alice --recipient "file://keys/alice-laptop.txt"
```

Files automatically get re-encrypted ("sealed") after each operation.
If you want to work in batches then add `--no-seal` and seal explicitly once at the end.

## Removing users

Removing users is also something only admins can do:

```bash
$ sesam kill --user alice
```

This will remove `alice` from all the access, delete any group that is now empty and then re-encrypt all files.

```admonish note
You can not remove the last admin. There has to be always at least one user.
```

### Auxiliary operations

There are a couple of operations that are worth knowing they exist,
but since they are not daily drivers we only briefly mentioned them.
By now you should be able to guess what they do:


```bash
# List all users
sesam user list
```

```bash
# Change the groups a user is in
sesam user change-groups --user alice --group a --group b

# Append, instead of overwriting:
sesam user change-groups --user alice --group-add c

# Can be also done by tell for existing users:
sesam tell --user alice --group a --group b

```

```bash
# Add one or more recipients to an existing user
sesam user add-recipient --user alice -r "..." -r "..."

# Can be also done by tell for existing users:
sesam tell --user alice --recipient "..."
```


```bash
# Remove one or more recipients from an existing user.
sesam user remove-recipient --user alice -r "..."

# Alternatively, invert it and delete all but the specified:
sesam user remove-recipient --user alice --all-except -r "..."
```


```bash
# Regenerate the signing key of a user (seldomly useful)
sesam user regen-sign-key --user alice
```


```bash
# Rename an existing user.
sesam user rename ellisch alice
```

