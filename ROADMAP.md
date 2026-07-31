# Roadmap

## 0.3.1 (current)

CLI encryption as the recommended workflow, an asset transformer as the
automatic alternative: config lives in
`pubspec.yaml` (or a dedicated `litert_crypto.yaml`), `encrypt`/`keyparts`
keep the embedded-key source in step with the key, and a transformer build
with stale key parts fails instead of shipping broken. On top of the 0.2.x
base: LRTC format v2 (AES-256-GCM on BoringSSL), the `EncryptedModel`
loader with no inference-runtime dependency, four key providers,
`KeyCache`, worker-isolate decryption.

## Next

- Remove the host toolchain requirement (cmake + C compiler, NASM on
  Windows x64) — a pure-Dart encrypt path or prebuilt host binaries, so
  builds and the CLI need no setup anywhere
- A `KeyCache` recipe over `flutter_secure_storage`, kept out of this package
  so it stays plugin-free
- Decrypt straight into the inference runtime's own buffer, so a model is
  never resident twice. Blocked on both ends today: no runtime exposes a
  buffer to fill, and the GCM engine returns a fresh buffer rather than
  filling one

## Decided against

Features deliberately left out, with the reasoning:
[design.md — Decided against](litert_crypto_docs/design.md#decided-against).
