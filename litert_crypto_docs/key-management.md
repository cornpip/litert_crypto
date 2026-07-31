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

## Key rotation

Rotating is just encrypting again with a fresh key:

1. Replace the key file: delete it and run `dart run litert_crypto keygen`.
2. Regenerate the embedded parts (if `key_parts_out` is set):
   `dart run litert_crypto keyparts`.
3. Rebuild the app. Models encrypted outside the build (downloaded ones):
   rerun `encrypt` and re-upload.
4. Ship the new assets and the app in the same release.

### The build-cache caveat (transformer mode)

The flutter tool caches a transformed asset keyed on the *asset's content and
the transformer entry in pubspec.yaml* — the key file is not one of its
inputs, because the tool has no idea the transformer reads it. So after a
rotation the next build can reuse ciphertext cached under the **old** key
while the app embeds the **new** key parts; nothing fails until decryption
does, at runtime. (The transformer's own key-parts freshness check cannot
catch this either — a cached asset skips the transformer process entirely.)

Two ways to force a re-encrypt, either works:

- **Bump `--key-id` in the transformer `args`** — editing pubspec.yaml
  invalidates the cached transform. You would bump it anyway: the number
  exists to stamp which key generation encrypted a file.
- **`flutter clean`** — wipes the build cache wholesale.

Clean builds (CI, fresh checkouts) never hit this: with no cache, every asset
is re-encrypted with the current key.

### `key_id` — letting two generations coexist

If two key generations must be served at once — users on the previous release
still fetch the old key from your server while new installs need the new
one — bump the key id when you rotate (`key_id` in the config, `--key-id` in
transformer args). The number is stamped into each encrypted asset's header
and reaches your `KeyProvider` as `KeyContext.keyId`, which is how it can
tell which generation's key to return.
