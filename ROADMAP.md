# Roadmap

## 0.1.0 (current)

LRTC format and codec, `EncryptedModel` loader with no runtime dependency,
`Embedded`/`Callback`/`Remote`/`Fallback` key providers, `KeyCache`, and the
`init` / `keygen` / `encrypt` CLI including generated key-part source.

## Next

- `check` CLI: fail a build when a plaintext model is still registered as an
  asset
- A `KeyCache` recipe over `flutter_secure_storage`, kept out of this package
  so it stays plugin-free
- Optional isolate decryption — a 10 MB model costs ~500 ms on a mid-range
  phone, which blocks the UI thread on the load path

## Decided against

Features deliberately left out, with the reasoning:
[design.md — Decided against](litert_crypto_docs/design.md#decided-against).
