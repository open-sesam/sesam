# What is Sesam?

<div style="text-align: center;">
  <img src="sesam_bg.png" width="400" />
</div>

`sesam` is a tool to manage secrets.

When developing and deploying software it is often required to store and load several secrets like database passwords, certificates or other credentials. Those should be stored encrypted and only the users requiring them should have access to them.

`sesam` allows leveled access with multiple users to those encrypted secrets and gives you a simple interface to manage both users and secrets.


```admonish note
The term *user* does not necessarily refer to a person. A user can also be a machine, like a server where `sesam` is installed.
```

## Features

- Declarative config as main interface.
- Different access levels through user groups.
- Secure - common crypto, minimal info leakage in rest.
- Familiarity to git users.
- Decentralized & offline ready.
- Safe to use (hard to accidentally push unencrypted secrets)
- Versioned - by wrapping git.
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
