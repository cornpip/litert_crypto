# Roadmap

## 0.3.0 (current)

Build-time encryption via a Flutter asset transformer: register a plaintext
model with `transformers: [package: litert_crypto]` and `flutter build`
encrypts it into the bundle. Config lives in `pubspec.yaml` (or a dedicated
`litert_crypto.yaml`), `keyparts` generates the embedded-key source, and a
build with stale key parts fails instead of shipping broken. On top of the
0.2.x base: LRTC format v2 (AES-256-GCM on BoringSSL), the `EncryptedModel`
loader with no inference-runtime dependency, four key providers, `KeyCache`,
worker-isolate decryption.

## Next

- Remove the host toolchain requirement from transformer builds (cmake +
  C compiler, NASM on Windows x64) — a pure-Dart encrypt path or prebuilt
  host binaries, so `flutter build` needs no setup anywhere
- A `KeyCache` recipe over `flutter_secure_storage`, kept out of this package
  so it stays plugin-free
- Decrypt straight into the inference runtime's own buffer, so a model is
  never resident twice. Blocked on both ends today: no runtime exposes a
  buffer to fill, and the GCM engine returns a fresh buffer rather than
  filling one

## Decided against

Features deliberately left out, with the reasoning:
[design.md — Decided against](litert_crypto_docs/design.md#decided-against).
