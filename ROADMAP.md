# Roadmap

## 0.3.1 (current)

CLI encryption as the recommended workflow, an asset transformer as the
automatic alternative: config lives in `pubspec.yaml` (or a dedicated
`litert_crypto.yaml`), `encrypt`/`keyparts` keep the embedded-key source in
step with the key, and a transformer build with stale key parts fails
instead of shipping broken. The transformer is not the default for now — an
upstream `dart run` concurrency bug
([dart-lang/sdk#63933](https://github.com/dart-lang/sdk/issues/63933)) can
crash multi-asset transformer builds on Windows. On top of the 0.2.x base:
LRTC format v2 (AES-256-GCM on BoringSSL), the `EncryptedModel` loader with
no inference-runtime dependency, four key providers, `KeyCache`,
worker-isolate decryption.

## Next

- A transformer package without the webcrypto dependency (pure-Dart encrypt
  path) — removes both the `dart run` staging race (dart-lang/sdk#63933)
  and the host toolchain requirement (cmake + C compiler, NASM on Windows
  x64), making the transformer the safe default again
- A `KeyCache` recipe over `flutter_secure_storage`, kept out of this package
  so it stays plugin-free
- Decrypt straight into the inference runtime's own buffer, so a model is
  never resident twice. Blocked on both ends today: no runtime exposes a
  buffer to fill, and the GCM engine returns a fresh buffer rather than
  filling one

## Decided against

Features deliberately left out, with the reasoning:
[design.md — Decided against](litert_crypto_docs/design.md#decided-against).
