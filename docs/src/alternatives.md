> **AI-generated.** This document was written by an AI assistant using training-data knowledge (cutoff Aug 2025). Verify specific claims before relying on them — project activity, feature sets, and security properties change.

# Secret Management Alternatives

## Why another tool?

- We like to have a decentralized tool that works well together with git.
- We need a tool that is easy to understand and reason about.
- None of the above decentralized tools support leveled access.
- Central tools are targeting really large organisations.

In general, our background is with git-secret. It was working kinda, but had way too much bugs, pitfalls, inconveniences and missing features to keep it for any longer.

## Decentralized / Git-native tools

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
| **sesam** | Go | 2025 | in development | transparent (clean/smudge, planned) + pre-commit | age / ChaCha20-Poly1305 |

¹ AES-CBC via OpenSSL — considered weaker than GCM/ChaCha20.  
² Works alongside git but requires explicit encrypt/decrypt invocation.  
³ Project is only weeks old at time of writing — feature surface and maintenance trajectory not yet established.

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
| [agebox](https://github.com/slok/agebox) | age recipients | ✓ | ✓ | ✗ |
| [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) | cluster RBAC | ✓ | ✓ | ✓ (cluster RBAC) |
| [cottage](https://github.com/sayanarijit/cottage) | age recipients | ✓ | ✓ (allow/deny globs) | ✗ |
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
| sesam | ✓ | ✓ | ✓ (encrypted, signed, hash-chained) | ✓ | ✓ |

---

## Env-file / app-config focused tools

A separate niche from sesam: these tools manage the `.env` files that
applications read at runtime, not arbitrary repo files (configs, certs,
key material). They typically operate per-value rather than per-file
and are tightly bound to the env-var injection workflow.

| Tool | Lang | Since | Encryption | Scope | Multi-user model | Audit / rotation |
|------|------|-------|------------|-------|------------------|------------------|
| [**dotenvx**](https://dotenvx.com) | JavaScript | 2023 | ECIES (secp256k1) + AES-256-GCM | values inside `.env` | shared private key, distributed out of band | `dotenvx rotate`, no audit log |
| [**varlock**](https://varlock.dev) | TypeScript | 2025 | optional / plugin-driven⁴ | `.env.schema` + values, plugin-resolved | delegated to plugins (1Password, AWS, …) | depends on plugin |
| [**secretspec**](https://secretspec.dev) | Rust | 2025 | none (delegates to backend) | declares which secrets an app needs | delegated to backend (keyring, 1Password, AWS Secrets Manager, Vault, …) | depends on backend |

⁴ varlock's primary security story is leak prevention (schema, scanning, log redaction) rather than a specific encryption scheme — encrypted local state is mentioned but not deeply documented.

**Why these don't really compete with sesam:** the unit of management
is environment variables consumed at runtime, not files in a repo. None
of them target the "store an arbitrary plaintext file encrypted in git
with a verifiable history of who could read it" use case. secretspec in
particular is not an encryption tool at all — it's a declarative façade
over existing centralized stores.

---

## Centralized / service-based tools

These require a running service or cloud dependency. Trade operational simplicity for availability risk.

| Tool | Model | Encryption | Audit log | Leveled access | Decl. config | Git workflow |
|------|-------|------------|-----------|----------------|--------------|--------------|
| [**HashiCorp Vault**](https://www.vaultproject.io) | self-hosted server | AES-GCM (transit engine) | ✓ (detailed) | ✓ (policies + roles) | ✓ (HCL) | env-inject or agent |
| [**Infisical**](https://infisical.com) | SaaS / self-hosted | AES-256-GCM | ✓ | ✓ (roles) | ✓ | env-inject, SDKs |
| [**Doppler**](https://www.doppler.com) | SaaS | AES-256 | ✓ | ✓ (roles) | ✓ | env-inject, CLI sync |
| [**1Password CLI**](https://developer.1password.com/docs/cli/) | SaaS (op) | AES-256-GCM | ✓ | ✓ (vault permissions) | partial | env-inject (`op run`), SDKs |
| [**AWS Secrets Manager**](https://aws.amazon.com/secrets-manager/) | AWS managed | AES-256 (KMS) | ✓ (CloudTrail) | ✓ (IAM policies) | ✓ (IaC/CDK) | SDK / env-inject |
| [**GCP Secret Manager**](https://cloud.google.com/secret-manager) | GCP managed | AES-256 (CMEK opt.) | ✓ (Cloud Audit) | ✓ (IAM roles) | ✓ (IaC/Terraform) | SDK / env-inject |
| [**Ansible Vault**](https://docs.ansible.com/ansible/latest/vault_guide/) | file-based (no server) | AES-256 | ✗ | ✗ | ✓ (playbooks) | committed ciphertext |

**When centralized tools win:** large teams, compliance requirements (SOC2, HIPAA), dynamic secrets (database credentials), or when you need secret leasing / TTLs.  
**When git-native tools win:** small teams, offline-first, no extra infrastructure, secrets version-controlled alongside code.

---

## sesam vs. closest alternatives

| | git-crypt | agebox | cottage | sesam |
|--|-----------|--------|---------|-------|
| Transparent git UX | ✓ | ✗ | ✗ | ✓ (planned) |
| Modern crypto (no GPG) | ✗ (GPG mode) | ✓ | ✓ | ✓ |
| Per-user access control | ✗ | ✓ | ✓ | ✓ |
| Declarative config | ✗ | ✓ | ✓ | ✓ |
| Leveled access (admin/user) | ✗ | ✗ | ✗ | ✓ |
| Signed + chained audit log | ✗ | ✗ | ✗ | ✓ |
| Rekeying on user removal | ✗ | manual | ✗ | ✓ |
| Production-ready | ✓ | ✓ | ✗ (very new) | ✗ (in development) |
