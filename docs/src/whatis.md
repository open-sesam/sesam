# What is Sesam?

<div style="text-align: center;">
  <img src="sesam_bg.png" width="400" />
</div>

**`sesam` is a tool for managing secrets in git.**

Software projects often required to store and load several secrets such as database passwords, certificates, API keys or other credentials. Those secrets should be stored encrypted and only be accessible to the users that actually need them.

`sesam` allows leveled access with multiple users to those encrypted secrets and gives you a simple interface to manage both users and secrets.

```admonish note
The term *user* does not necessarily refer to a person. A user can also be a machine, like a server where `sesam` is installed.
```

You might think of a password manager now, which is not too far off. A password manager is usually targeted at managing individual secrets,
while a secret manager is focused on sharing selected secrets with other users in a team and machines. If you already know what a secret manager is then you might be interested in [Why we built another tool](./alternatives.md).

## Features

- Signed, hash-chained and encrypted audit log.
- Per-secret integrity checks with root-hash verification.
- Support for SSH keys, age keys and age plugin identities.
- Hardware-backed identities via age plugins (e.g. YubiKey-style workflows).
- Forge recipient shortcuts for GitHub, GitLab and Codeberg.
- Both declarative (config) and imperative (CLI) workflows possible.
- Different access levels through user groups.
- Secure - common crypto, minimal info leakage in rest.
- High level of integration with `git`.
- Familiarity to `git` users.
- Versioned - by wrapping git.
- Decentralized & offline ready.
- Safe to use (hard to accidentally push unencrypted secrets)
- Optional pre-commit and post-checkout hooks.
- Scriptable via CLI interface.
- Fast encryption and decryption.
- Almost zero dependencies.
- Support for rotation and exchange of secrets.

In short, `sesam` fits well the [GitOps model](https://about.gitlab.com/topics/gitops/) of infrastructure.

## Learning

How to use this manual:

- Go to [Installation](./installation.md) to grab your copy of `sesam`.
- Go to [Basic Usage](./secret.md) to walk through what it can do.
- Go to [Advanced Usage](./template.md) if you need some more depth.
- Go to [Reference](./config_ref.md) if you need to look up things later on.

## The name

It is a reference to [Ali Baba and the Forty Thieves](https://en.wikipedia.org/wiki/Ali_Baba_and_the_Forty_Thieves)
out of the story collection [One Thousand and One Nights](https://en.wikipedia.org/wiki/One_Thousand_and_One_Nights).
In this story the cave opens upon calling the passphrase *"Open, Sesam!"* revealing a hidden cave full of gold and treasures.

You see this scene depicted on the [landing page](https://opensesam.org/).

The logo is a sesame pod, with the seeds replaced by cute little keys.
