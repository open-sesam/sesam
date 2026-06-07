# Secret Management Alternatives

## Why another tool?

There are five reasons why we've set out to build our own tool.

### 1. We like to have a decentralized tool that works well together with git

Existing tools only have minor or inconsequential integration in `git`. From
our perspective, building on top of `git` makes a lot of sense. It's everywhere
where developers are, it gives us versioning, transport to remotes and a huge
ecosystem for free. Also, it offers plenty of integrations for tools to extend
it. From what we know those have never been fully maxed out by existing tools
yet.

### 2. None of the existing decentralized tools support leveled access

There are centralized tools like `Infisical` that support that. In decentralized
tools it is harder to implement a secure user management system. Even harder
when it should not completely duplicate the user management of other existing tools.

In professional software development, there will always be different access levels.
For example: An intern should not have access to all secrets required to deploy prod.
One could create several repositories, but that is obviously tedious.

Instead we support users that are easy to add if you are using one of the
popular git forges. We can even warn you, if a user is not there anymore or
changed their public keys. Later versions might even extend that (e.g. adding
constraints that a user has to be part of a org).

### 3. Central tools are targeting large organisations

While centralized tools will work fine overall, they require some setup, need
to be constantly running and in some cases cannot be self-hosted - in the
latter case the trust model becomes "trust me, bro".

We consider this to be a matter of preference, there is nothing wrong with them
if you prefer this model. However, we want to add an alternative for small to
middle-sized teams and individuals.

### 4. Modern cryptography and security concept

Most existing decentralized tools use PGP/OpenGPG. While this certainly works,
it is a standard that has a lot of pitfalls and is honestly a bit dusty. It
also has little overlap with the typical developer tooling, where everyone
already has an SSH key. That's why we've chosen `age` as the main ingredient.

We wanted to also build a more rounded version, security wise. Existing tools
encrypt secrets at rest, but don't really detect if secrets were just exchanged
by other encrypted files or if even the integrity was altered. They might
protect against leaking secrets, but not against a person having access to the
repo exchanging the content with something evil.

Our audit-log based design can build trust and detect issues easily.
If your secrets still get leaked we are aiming at support rotation natively.

### 5. We need a modern, ergonomic & easy-to-understand tool

In general, our background is with [git-secret](https://git-secret.io). It
carried our secrets for several years fine and we are thankful it exists.
However, it has many pitfalls and some trivial operations require weird
invocations that will certainly confuse new developers.

Modern CLI tools have leveled up a bit and we take inspiration from them by
offering a friction-less usage experience. We tried to reduce interaction with
the tool where possible and try to make the rest as easy and discoverable as
possible. As far as we know, we are also the only tool supporting declarative
workflows (i.e. secrets and users are configured and then applied similar in
concept to docker-compose or terraform).


## Decentralized / Git-native tools

If you want a full overview of what existing tools we are aware of: Please read on.
Let us also know if you found something wrong here.

The table below maps the five reasons above onto the tools most similar to sesam:

| | [git-crypt](https://github.com/AGWA/git-crypt) | [git-secret](https://git-secret.io) | [sops](https://github.com/getsops/sops) | [agebox](https://github.com/slok/agebox) | [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) | sesam |
|--|--|--|--|--|--|--|
| **1. Works natively with git** | | | | | | |
| Transparent git UX (clean/smudge) | ✓ | ✗ | ✗ | ✗ | ✗ | ✓           |
| **2. Leveled, per-user access** | | | | | | |
| Named per-user recipients | ✓¹ | ✓¹ | ✓ | ✓ | ✗ | ✓ |
| Per-file selective access | ✗ | ✗ | ✓ | ✗ | ✗ | ✓ |
| Leveled access (admin / user roles) | ✗ | ✗ | ✗ | ✗ | ✓² | ✓ |
| **3. Decentralized — no service to run** | | | | | | |
| Self-hosted / offline, no server | ✓ | ✓ | ✓ | ✓ | ✗³ | ✓ |
| **4. Modern crypto & verifiable security** | | | | | | |
| Modern crypto (no GPG) | ✗⁴ | ✗ | ✓⁵ | ✓ | ✓ | ✓ |
| Signed + hash-chained audit log | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Detects content swaps / history tampering | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Rekey on user removal | ✗ | manual | manual⁶ | manual | ✗ | ✓ (automatic) |
| **5. Modern, declarative UX** | | | | | | |
| Declarative desired-state + `apply` | ✗ | ✗ | partial⁷ | ✗⁸ | partial⁹ | ✓ |
| Production-ready | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ (in development) |

¹ Per-user identities come via GPG keys.  
² Access levels are enforced by Kubernetes cluster RBAC at runtime, not in git.  
³ Needs an in-cluster controller to decrypt; not usable offline or outside Kubernetes.  
⁴ AES-256, but GPG is used to share the symmetric key with each user.  
⁵ Achievable with the `age` or KMS backends; PGP remains an option.  
⁶ `sops updatekeys`, run manually per file.  
⁷ `.sops.yaml` `creation_rules` apply only to newly-created files; existing files need a manual `sops updatekeys`.  
⁸ `.ageboxreg.yml` is an auto-generated tracking file, not an authored desired-state spec.  
⁹ `SealedSecret` manifests are reconciled by the controller (GitOps), but users/access live in separate cluster RBAC, not the spec.


### Overview


| Tool | Lang | Since | Maintenance | Git integration | Encryption |
|------|------|-------|-------------|-----------------|------------|
| [**git-crypt**](https://github.com/AGWA/git-crypt) | C++ | 2013 | slow | transparent (clean/smudge) | AES-256-GCM |
| [**Transcrypt**](https://github.com/elasticdog/transcrypt) | Bash | 2014 | active | transparent (clean/smudge) | AES-256-CBC¹ |
| [**git-secret**](https://git-secret.io) | Bash | 2015 | active | explicit hide/reveal | GPG (RSA/curve) |
| [**keyringer**](https://keyringer.pw) | Bash | 2012 | dormant | explicit encrypt/decrypt | GPG |
| [**BlackBox**](https://github.com/StackExchange/blackbox) | Bash | 2013 | dormant | explicit encrypt/decrypt | GPG |
| [**gopass**](https://www.gopass.pw) | Go | 2017 | active | git backend (pass-compatible) | GPG / age |
| [**sops**](https://github.com/getsops/sops) | Go | 2015 | very active | none native² | age / PGP / KMS |
| [**agebox**](https://github.com/slok/agebox) | Go | 2021 | moderate | none native² | age (X25519) |
| [**Sealed Secrets**](https://github.com/bitnami-labs/sealed-secrets) | Go | 2018 | active | commit sealed YAML | RSA-OAEP + AES-GCM |
| [**cottage**](https://github.com/sayanarijit/cottage) | Rust | 2026 | new³ | explicit encrypt/decrypt (`ctg`) + env-inject | age (X25519 / ssh) |
| **sesam** | Go | 2025 | in development | transparent (smudge, diff, merge) + pre-commit | age / ChaCha20-Poly1305 |

¹ AES-CBC via OpenSSL — considered weaker than GCM/ChaCha20.  
² Works alongside git but requires explicit encrypt/decrypt invocation.  
³ Project is only weeks old at time of writing - feature surface and maintenance trajectory not yet established.

### Access control


| Tool | Multi-user | Decl. config | Per-file ACL | Leveled access |
|------|------------|--------------|--------------|----------------|
| [git-crypt](https://github.com/AGWA/git-crypt) | GPG or symmetric | ✗ | ✗ | ✗ |
| [Transcrypt](https://github.com/elasticdog/transcrypt) | symmetric (shared secret) | ✗ | ✗ | ✗ |
| [git-secret](https://git-secret.io) | GPG keyring | ✗ | ✗ | ✗ |
| [keyringer](https://keyringer.pw) | GPG keyring | ✗ | ✗ | ✗ |
| [BlackBox](https://github.com/StackExchange/blackbox) | GPG keyring | ✗ | ✗ | ✗ |
| [gopass](https://www.gopass.pw) | team mounts | ✗ | ✗ | ✗ |
| [sops](https://github.com/getsops/sops) | yes | ✓ | ✓ | ✗ |
| [agebox](https://github.com/slok/agebox) | age recipients | ✗ | ✗ | ✗ |
| [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) | cluster RBAC | ✗ | ✓ | ✓ (cluster RBAC) |
| [cottage](https://github.com/sayanarijit/cottage) | age recipients | ✗ | ✓ (allow/deny globs) | ✗ |
| sesam | age recipients | ✓ | ✓ | ✓ |


### Security


| Tool | No GPG | Signed entries | Audit log | Key rotation | Rekey on removal |
|------|--------|----------------|-----------|--------------|-----------------|
| [git-crypt](https://github.com/AGWA/git-crypt) | ✗ | ✗ | ✗ | poor (manual) | ✗ |
| [Transcrypt](https://github.com/elasticdog/transcrypt) | ✗ | ✗ | ✗ | poor | ✗ |
| [git-secret](https://git-secret.io) | ✗ | ✗ | ✗ | manual | ✗ |
| [keyringer](https://keyringer.pw) | ✗ | ✗ | ✗ | manual | ✗ |
| [BlackBox](https://github.com/StackExchange/blackbox) | ✗ | ✗ | ✗ | manual | ✗ |
| [gopass](https://www.gopass.pw) | partial | ✗ | ✗ | manual | ✗ |
| [sops](https://github.com/getsops/sops) | ✓ | ✗ | ✗ | `sops rotate` | manual |
| [agebox](https://github.com/slok/agebox) | ✓ | ✗ | ✗ | partial | manual |
| [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) | ✓ | ✗ | k8s audit | key renewal | ✗ |
| [cottage](https://github.com/sayanarijit/cottage) | ✓ | ✗ | ✗ (checksum only) | not documented | ✗ |
| sesam | ✓ | ✓ | ✓ (encrypted, signed, hash-chained) | manual | ✓ |

---

## Env-file / app-config focused tools

This is a bit of a separte niche: These tools manage `.env` files. Their
smallest level of secret is an environment variable that is being managed,
while for `sesam` it is files.

They fit well for use cases where you inject your configuration via environment
and don't have a lot of complete files. In some sense `sops` could be added here as well.


| Tool | Lang | Since | Encryption | Scope | Multi-user model | Audit / rotation |
|------|------|-------|------------|-------|------------------|------------------|
| [**dotenvx**](https://dotenvx.com) | JavaScript | 2023 | ECIES (secp256k1) + AES-256-GCM | values inside `.env` | shared private key, distributed out of band | `dotenvx rotate`, no audit log |
| [**fnox**](https://github.com/jdx/fnox) | Rust | 2025 | age (X25519 / SSH) or cloud KMS (AWS / Azure / GCP)⁵ | per-value in `fnox.toml`, env-inject via `fnox exec` | age recipients or KMS IAM | no audit log; rotation not documented |
| [**varlock**](https://varlock.dev) | TypeScript | 2025 | optional / plugin-driven⁴ | `.env.schema` + values, plugin-resolved | delegated to plugins (1Password, AWS, …) | depends on plugin |
| [**secretspec**](https://secretspec.dev) | Rust | 2025 | none (delegates to backend) | declares which secrets an app needs | delegated to backend (keyring, 1Password, AWS Secrets Manager, Vault, …) | depends on backend |

⁴ varlock's primary security story is leak prevention (schema, scanning, log redaction) rather than a specific encryption scheme - encrypted local state is mentioned but not deeply documented.  
⁵ A jack-of-all-trades: behind one `fnox.toml` it spans encryption providers (age/SSH, AWS/Azure/GCP KMS), remote backends (Vault, 1Password, Infisical, cloud secret managers) and even short-lived credential leasing. It leans decentralized — the default age/SSH path keeps secrets git-native with no server — but can equally act as a thin client over a centralized store. Either way the unit is an individual value (per key, providers mixable), not a file.

---

## Centralized / service-based tools

These tools make the most sense when you are operating a large organization, need dynamic secrets or have compliance requirements.


| Tool | Model | Encryption | Audit log | Leveled access | Decl. config | Git workflow |
|------|-------|------------|-----------|----------------|--------------|--------------|
| [**HashiCorp Vault**](https://www.vaultproject.io) | self-hosted server | AES-GCM (transit engine) | ✓ (detailed) | ✓ (policies + roles) | ✓ (HCL) | env-inject or agent |
| [**Infisical**](https://infisical.com) | SaaS / self-hosted | AES-256-GCM | ✓ | ✓ (roles) | ✓ | env-inject, SDKs |
| [**Doppler**](https://www.doppler.com) | SaaS | AES-256 | ✓ | ✓ (roles) | ✓ | env-inject, CLI sync |
| [**1Password CLI**](https://developer.1password.com/docs/cli/) | SaaS (op) | AES-256-GCM | ✓ | ✓ (vault permissions) | partial | env-inject (`op run`), SDKs |
| [**AWS Secrets Manager**](https://aws.amazon.com/secrets-manager/) | AWS managed | AES-256 (KMS) | ✓ (CloudTrail) | ✓ (IAM policies) | ✓ (IaC/CDK) | SDK / env-inject |
| [**GCP Secret Manager**](https://cloud.google.com/secret-manager) | GCP managed | AES-256 (CMEK opt.) | ✓ (Cloud Audit) | ✓ (IAM roles) | ✓ (IaC/Terraform) | SDK / env-inject |
| [**Ansible Vault**](https://docs.ansible.com/ansible/latest/vault_guide/) | file-based (no server) | AES-256 | ✗ | ✗ | ✓ (playbooks) | committed ciphertext |

