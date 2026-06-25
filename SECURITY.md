# Security Policy

## Overview

sesam is a secrets manager for Git repositories. Because it handles sensitive credentials
and cryptographic material, we take security issues extremely seriously. We appreciate the
efforts of security researchers and users who responsibly disclose vulnerabilities.

---

## Supported Versions

We provide security fixes for the following versions:

| Version        | Supported          |
|----------------|--------------------|
| Latest release | ✅ Yes              |
| Previous minor | ✅ Yes (critical fixes only) |
| Older releases | ❌ No               |

We strongly recommend always running the latest stable release.

---

## Scope

The following are considered in scope for security reports:

- **Secret exposure** — any code path that could cause secrets to be leaked to stdout,
  logs, environment variables, or the filesystem in plaintext
- **Cryptographic weaknesses** — use of weak algorithms, insecure key derivation, or
  improper IV/nonce handling
- **Access control bypass** — unauthorized access to encrypted secrets or the sesam
  keystore
- **Dependency vulnerabilities** — high/critical CVEs in direct dependencies that affect
  sesam's security posture
- **Git history exposure** — scenarios where sesam-managed secrets could be inadvertently
  committed or reconstructed from Git history
- **CLI injection / path traversal** — malicious input that escapes intended boundaries

The following are **out of scope**:

- Vulnerabilities in the underlying OS, Git installation, or system keychain that are
  not specific to sesam
- Social engineering attacks
- Issues only reproducible on end-of-life operating systems or runtimes
- Rate limiting or denial-of-service issues with no security impact

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

### Preferred channel — GitHub private vulnerability reporting

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Fill in the form with the details below and submit.

### What to include

Please provide as much of the following as possible:

- A clear description of the vulnerability and its potential impact
- The affected version(s) of sesam
- Step-by-step reproduction instructions or a proof-of-concept (PoC)
- Any relevant code references, configuration, or environment details
- Your suggested severity (Critical / High / Medium / Low) and rationale
- Whether you have already developed a patch or mitigation

---

## Disclosure Policy

We follow a **coordinated disclosure** model:

1. Reporter submits vulnerability privately.
2. We confirm receipt within **48 hours**.
3. We triage and assign a severity within **5 business days**.
4. We work with the reporter to develop and validate a fix.
5. We release a patched version and publish a security advisory.
6. The reporter may publicly disclose the vulnerability **14 days** after the patch is
   released, or earlier by mutual agreement.

We ask reporters to refrain from public disclosure until a fix is available, except where
required by law or in cases of active exploitation in the wild.

---

## Severity Classification

We use the following severity levels, aligned with
[CVSS v3.1](https://www.first.org/cvss/):

| Severity | Description | Target Fix Time |
|----------|-------------|-----------------|
| **Critical** | Direct plaintext secret exposure or full keystore compromise | 24–48 hours |
| **High** | Indirect secret exposure, significant cryptographic weakness | 7 days |
| **Medium** | Limited-scope data exposure, requires user interaction | 30 days |
| **Low** | Defense-in-depth issues, hardening improvements | Next minor release |

---

## Security Updates

Security advisories are published via:

- [GitHub Security Advisories](./security/advisories) for this repository
- Release notes in [`CHANGELOG.md`](./CHANGELOG.md)

We recommend watching this repository for releases to receive timely notifications.

---

## Safe Harbour

We will not pursue legal action against researchers who:

- Report vulnerabilities privately and in good faith following this policy
- Do not access, modify, or delete data beyond what is necessary to demonstrate the issue
- Do not disrupt sesam services or other users
- Do not exploit the vulnerability for personal gain
