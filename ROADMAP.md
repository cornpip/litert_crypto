# Roadmap

## 0.2.0 (current)

LRTC format and codec, `EncryptedModel` loader with no runtime dependency,
`Embedded`/`Callback`/`Remote`/`Fallback` key providers, `KeyCache`, and the
`init` / `keygen` / `encrypt` CLI including generated key-part source.
Decryption runs on a worker isolate by default and holds one buffer, not three.

## Next

- `check` CLI: fail a build when a plaintext model is still registered as an
  asset
- A `KeyCache` recipe over `flutter_secure_storage`, kept out of this package
  so it stays plugin-free
- Decrypt straight into the inference runtime's own buffer. The runtime copies
  the plaintext into native memory, so a model is briefly resident twice; no
  runtime exposes a buffer to fill, which is what it would take to avoid that

## Decided against

Features deliberately left out, with the reasoning:
[design.md — Decided against](litert_crypto_docs/design.md#decided-against).
