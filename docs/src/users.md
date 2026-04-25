# Managing users

## Managing users via config

As mentioned during [Initialization](/init.md) there is always at least one admin user.
When you created your admin repo you will see something like this in your config:

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
`alice`. Many forges support API to fetch this information. You can also use
`gitlab:` or `codeberg:`. This makes adding new users really easy, as you most
likely already know the user name of your peer on your favorite forge.
The public key will be fetched only once initially and the result is cached. Apart from the first time there is no online access required therefore.
* Peter on the other hand might not have an forge account. Maybe he also has an awful long RSA key that you don't want to put in the config verbatim. In this case you can just create a file in the repo and add it there.
- The key of `bob` was deferred from the identity used during init. If you use the same public key for (e.g.) your GitHub account you can also write something like `github:bob` there.


Once we've changed the config we can this command, which should be familiar by now. This will then adjust the repository state accordingly:

```
$ sesam apply
- added user `alice`
- added user `peter`
```

Changing groups later works the same way.

```note
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
$ sesam reveal --pull
```

## Managing users via CLI

You can have the same effect without editing configs - which is nice for scripting:

```bash
# Add users like above:
$ sesam tell --user alice --desc "Mrs. Wonderland" --pub "github:alice"
$ sesam tell --user peter --desc "Peter Lustig" --pub "file://keys/peter.txt"
# --access can be given several times:
$ sesam add --path some_password.txt --access deployment
```

Files automatically get re-encrypted ("sealed").

## Removing users

Removing users is also something only admins can do:

```bash
$ sesam kill alice
```

This will remove `alice` from all the access, delete any group that is now empty and then re-encrypt all files.

```admonish note
You can not remove the last admin. There has to be always at least one user.
```
