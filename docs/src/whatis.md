# What is Sesam?

<div style="text-align: center;">
  <img src="sesam_bg.png" width="400" />
</div>

**`sesam` is a tool to manage secrets in git.**

When developing and deploying software it is often required to store and load several secrets like database passwords, certificates or other credentials. Those should be stored encrypted and only the users requiring them should have access to them.

`sesam` allows leveled access with multiple users to those encrypted secrets and gives you a simple interface to manage both users and secrets.

```admonish note
The term *user* does not necessarily refer to a person. A user can also be a machine, like a server where `sesam` is installed.
```

You might think of a password manager now, which is not too far off. A password manager is usually targeted at managing individual secrets,
while a secret manager is focused on sharing some of those secrets with other users in a team and machines. If you already know what a secret manager is then you might be interested in [Why we built another tool](/alternatives.md).

## Features

- High level of integration with `git`.
- Both declarative (config) and imperative (CLI) workflows possible.
- Different access levels through user groups.
- Secure - common crypto, minimal info leakage in rest.
- Familiarity to `git` users.
- Decentralized & offline ready.
- Safe to use (hard to accidentally push unencrypted secrets)
- Versioned - by wrapping git.
- Scriptable via CLI interface.
- Fast encryption and decryption.
- Almost zero dependencies.
- Support for rotation and exchange of secrets.
- Somewhat¹ fast.

In short, `sesam` fits well the [GitOps model](https://about.gitlab.com/topics/gitops/) of infrastructure.

<small>
¹ <i>somewhat fast</i> is the new <i>🚀 blazingly fast 🚀</i> - benchmarks will follow later.
</small>

## Who is it for?

- Open source developers wanting to store secrets in their repos and give only their co-developers access.
- Small to mid-sized teams wanting to have different access levels in their secrets.
- Individuals wanting to store secrets in their git repos, even if it's just a single user.
- Machine users that need a scriptable tool.

## Learning

How to use this manual:

- Go to [Installation](./installation.md) to grab your copy of `sesam`.
- Go to [Basic Usage](./secret.md) to walk through what it can do.
- Go to [Advanced Usage](./template.md) if you need some more depth.
- Go to [Reference](./config_ref.md) if you need to look up things later on.

## The name

It is a reference to [Ali Baba and the Forty Thieves](https://en.wikipedia.org/wiki/Ali_Baba_and_the_Forty_Thieves)
out of the story collection [One Thousand and One Nights](https://en.wikipedia.org/wiki/One_Thousand_and_One_Nights).
In this story the cave opens upon calling the passphrase *"Open, Sesam!"*

You see this scene depicted on the [landing page](https://opensesam.org/).

The logo is a sesame pod, with the seeds replaced by cute little keys.
