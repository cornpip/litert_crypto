# Roadmap

## 0.2.0 (current)

LRTC format and codec, `EncryptedModel` loader with no runtime dependency,
`Embedded`/`Callback`/`Remote`/`Fallback` key providers, `KeyCache`, and the
`init` / `keygen` / `encrypt` CLI including generated key-part source.
Decryption is AES-256-GCM on BoringSSL (measured 1.2 ms/MB on an AES-NI
desktop) and runs on a worker isolate by default.

## Next

- `check` CLI: fail a build when a plaintext model is still registered as an
  asset
- A `KeyCache` recipe over `flutter_secure_storage`, kept out of this package
  so it stays plugin-free
- Decrypt straight into the inference runtime's own buffer, so a model is
  never resident twice. Blocked on both ends today: no runtime exposes a
  buffer to fill, and the GCM engine returns a fresh buffer rather than
  filling one

## Decided against

Features deliberately left out, with the reasoning:
[design.md — Decided against](litert_crypto_docs/design.md#decided-against).
