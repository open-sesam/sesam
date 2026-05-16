# Hardware identities (age plugins)

Sesam identities can live on hardware tokens via the [age plugin
protocol][age-plugin-protocol]. The headline use case is a YubiKey via PIV,
but sesam's support is generic: any age plugin works once its binary is on
`$PATH`.

[age-plugin-protocol]: https://github.com/C2SP/C2SP/blob/main/age-plugin.md

## What this gets you

- **No private key on disk.** The plugin keeps the secret material on the
  token; sesam only ever sees the public recipient (`age1yubikey1…`) and
  the identity stub (`AGE-PLUGIN-YUBIKEY-1…`).
- **Same `-i / --identity` flow.** A plugin identity file goes in the same
  `--identity` slot as a software age key. Multiple `-i` flags still work,
  so you can stack a backup software key behind a hardware key.
- **Per-secret access checks are unchanged.** The plugin only handles the
  asymmetric key step; signing of audit entries still uses sesam's own
  Ed25519 keys, stored encrypted to your hardware-protected recipient.

## Recommended plugin: YubiKey via PIV

`age-plugin-yubikey` uses the YubiKey's PIV applet for on-device ECDH, with
PIN cached per PC/SC session and touch cached for 15 s. That makes bulk
operations (revealing many secrets in one `sesam reveal`) pleasant: one PIN,
one touch, dozens of files. Install it from your distribution, `brew install
age-plugin-yubikey`, or `cargo install age-plugin-yubikey`.

```sh
# Generate a new YubiKey-backed identity.
age-plugin-yubikey --generate --pin-policy once --touch-policy cached
# → writes identity file (AGE-PLUGIN-YUBIKEY-1…) and prints the recipient
#   (age1yubikey1…).
```

Add the new user to your sesam repo by passing the recipient:

```sh
sesam tell --user alice --recipient age1yubikey1… --group dev
```

Alice points sesam at her identity file:

```sh
sesam reveal --identity ~/age-yubikey-identity.txt
```

## Other plugins

- `age-plugin-fido2-hmac` — any FIDO2 token with the `hmac-secret`
  extension (Swissbit, Nitrokey, SoloKey, …). Note: this category forces
  user-presence on every operation, so a `sesam reveal` over many files
  means many taps.
- `age-plugin-openpgp-card` — OpenPGP smartcards (YubiKey OpenPGP applet,
  Nitrokey 3, Nitrokey Pro 2).
- `age-plugin-tpm` — TPM 2.0.
- `age-plugin-se` — Apple Secure Enclave.

## Identity file format

Sesam reads the file the plugin emits as-is. It must contain at least:

```
# public key: age1yubikey1…
AGE-PLUGIN-YUBIKEY-1…
```

The `# public key:` (or `# recipient:`) header is **required** — sesam needs
the recipient encoding to map your identity back to the user entry in the
audit log, and the plugin protocol does not expose that from the identity
string alone. `age-plugin-yubikey` and friends emit it by default.

## Git filter behaviour

The smudge/clean git filters do not prompt for plugin interaction. If your
only loaded identity is a plugin one and you trigger a checkout, sesam logs a
warning and leaves the working tree's `.sesam` files as ciphertext; run
`sesam reveal` interactively afterwards. The sesam filter is not marked
`required`, so `git checkout` itself never fails because of a missing
hardware tap.

If you mix software and plugin identities under `-i`, the software ones run
during checkout and the plugin one stays inert — the best of both worlds for
users who want hardware-backed daily use and a sealed software backup.

## Signing keys

Sesam's per-user Ed25519 signing key (used to author audit log entries)
stays software-encrypted in `.sesam/signkeys/<user>.age`, encrypted to your
hardware-backed recipient. The first audit operation in a session unlocks
the signing key via the plugin; subsequent operations reuse it in memory.

Moving signing to the hardware token would require an Ed25519-capable applet
(OpenPGP card supports it; PIV does not) and is not currently implemented.
