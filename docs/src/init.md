# Init

## Prerequisites

`sesam` relies a lot on `git` for some functionality. You can either **use an existing repository** to manage your secrets in
or you can create a whole new one. If you use an existing repository we recommend an empty sub-directory to manage
your secret files in. The `.sesam` directory does not need to be on the same level as the `.git` folder.

```admonish warning
Sesam relies on git history to be linear. You should therefore disable `git push --force`
in your repository, if possible. Most git forges allow this in their settings (example: [GitHub](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#allow-force-pushes))

If force pushes are possible, someone could truncate the audit log (see [Design](/design.md) for more info).
```


## Creating a new repository

In the folder you've selected run:

```bash
$ sesam init --user bob --identity ~/.ssh/bobs_key --commit
```

Some things to note here:

- This command will do the following:
  - Create a folder `.sesam/` in the current directory.
  - Create a default config file in `sesam.yml`. It is a declarative config describing 
  - Create a `.gitignore` that ignores everything but `.sesam/` and `.sesam.yml`. This is to protect revealed secret so they never get accidentally added to git.
  - It will also create a first secret: `README.sesam`. Read it for a condensed version of this tutorial.
- The `--commit` will add commit directly. Remove it if you don't want that.
- You need to specify an initial user. This user will be the fist admin. `sesam` has the concept of users with different access levels. As admin, `bob` has access to all secrets and can also create new users.
- Every user needs an **identity** - a cryptographic way to prove he is this specific user.

## Identities

`sesam` supports the following keys as identity:

  - SSH Keys (RSA and ed25519)
  - [Age Keys](https://github.com/FiloSottile/age)

If you want to use several of them you can also pass `--identity` (or short `-i`) several times. Then `sesam` will use all of them for encryption and decryption.

**You are responsible for storing your identity in a safe place.** You should not store it as part of the sesam repository.

```admonish note
The list of possible identities will be likely supported in future releases with things like Yubikeys. Being based on `age` allows us to use their plugin system with relatively small effort.
```

## Recipients

Every user of `sesam` has at least one **recipient**. Think of it as the public part to the identity. While only you possess your **identity**, everyone has access to all **recipients**.
