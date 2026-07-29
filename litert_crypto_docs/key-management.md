# Where the key lives — what actually determines protection

Encrypting the model is the easy half. What decides how much protection you
actually get is whether the key ships with the app. This document lays out the
options tier by tier; the [README](../README.md) shows how each one plugs in
through `KeyProvider`.

## Tier 1 — the key is in the build

These are ordered by how much work extraction takes. Every one of them still
ships the key, so none of them is a boundary: they buy time, not safety.

| | Extraction | Effort |
|---|---|---|
| Key file bundled as an asset | unzip the app, read the file | none — never do this |
| One Dart literal | `strings` over the AOT snapshot | trivial |
| **XOR-combined parts** (`EmbeddedKeyProvider.fromParts`) | find both arrays, notice they are combined | low — needs reading code, not scanning |
| Derived in native code (your own FFI, via `CallbackKeyProvider`) | disassemble the `.so` | moderate |

`--obfuscate --split-debug-info` raises all of these — but only against
*static* analysis. A debugger or a hooking framework reads the key out of
memory at runtime no matter how it was hidden, so treat Tier 1 as "stops casual
extraction from the distributed artifact".

## Tier 2 — the key does not ship

This is the qualitative jump: someone holding only your app cannot decrypt
anything, because the material simply is not there.

| | Key comes from | What now gates access |
|---|---|---|
| Entitlement file (`CallbackKeyProvider`) | A license the user was issued | Your issuing process; works offline |
| Server delivery (`RemoteKeyProvider`) | Your endpoint | Whatever your server checks — attestation on mobile, a user credential elsewhere |
| Cached in platform secure storage (`KeyCache` over Keystore/Keychain) | A fetched key, persisted in the OS's hardware-backed store | The OS protects it at rest; it still enters app memory to decrypt |

Moving up a tier does not require touching the encrypted assets or the load
call — only the `keyProvider` argument changes, which is what the abstraction
is for.

Even in Tier 2, the plaintext model exists in memory while inference runs. That
limit is inherent to on-device inference.

## The repository is part of the trust boundary

With `EmbeddedKeyProvider` the generated key parts (`key_parts_out`) are
committed source, and the plaintext models usually sit in the repository too —
so **repository access is model access**. No reverse engineering required, and
that access is often granted more widely than the signed build is.

The XOR split only keeps a finished key out of the shipped binary; anyone with
the source recovers the key by XOR-ing the parts. Either treat the repository
as inside your trust boundary, or move the key out of the app (Tier 2).

## A server moves the secret; it does not gate it

Fetching the key remotely takes the secret out of your binary, but it does
**not** decide who deserves a key — that gate is your server's job:

- On mobile, verifying a **Play Integrity / App Attest** token before
  responding is what gives the endpoint teeth.
- On desktop there is no such attestation, so the gate has to be a credential
  the user holds (license, account login).
- Without a gate, an attacker simply asks your server for the key like any
  other client.
