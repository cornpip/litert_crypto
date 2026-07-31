# litert_crypto — design notes

Internals and the reasoning behind them. For installation and usage, see the
[README](../README.md); for choosing where your key lives, see
[key-management.md](key-management.md); for why the Windows host build wants
NASM and what we plan to do about it, see
[host-build-nasm.md](host-build-nasm.md).

## The LRTC file format

```
[magic "LRTC" (4B)] [version (1B)] [keyId (2B, BE)] [labelLen (1B)]
[label (labelLen B, UTF-8)] [IV (12B)] [ciphertext ‖ GCM tag (16B)]
```

This is format **version 2**. Version 1 (AES-CTR + HMAC-SHA256, written by
litert_crypto 0.1.0) is refused with a re-encrypt hint — the format changed
together with the crypto engine, and re-running `dart run litert_crypto
encrypt` is the whole migration.

The **entire model file** is encrypted, first byte to last — graph structure and
weights alike. What ships is the envelope above, and nothing of the original
`.tflite` (not even its `TFL3` identifier) survives in the clear.

The header is **plaintext — authenticated, not hidden**. Anyone opening the file
reads the label, which is why it defaults to the file's own name (the asset name
in transformer mode, the *output* name in the CLI): that name already appears in
the shipped bundle, so it gives nothing away that unzipping would not. Naming
the file generically is therefore enough; pass an explicit label only if you
want it to differ from the file name.

`keyId` (uint16) exists for key rotation: a `KeyProvider` receives it in
`KeyContext` and can tell key generations apart when two must be supported at
once.

Outside Flutter (build scripts, backends) the same format is available through
the Flutter-free entrypoint `package:litert_crypto/codec.dart`.

## Cipher choice: AES-256-GCM on BoringSSL

The codec runs on BoringSSL through `package:webcrypto` (dart:ffi), and the
whole seal/open is a single native call that uses the CPU's AES and GHASH
instructions — present on every ARMv8 phone and on x86-64 desktops. Measured
on an AES-NI desktop: 1.2 ms/MB, a 72 MB model in 87 ms.

**Version 1 chose the opposite trade.** In pure Dart, GCM measured ~3x slower
than CTR + HMAC-SHA256 (GHASH has no hardware to lean on there), so v1 was
CTR with encrypt-then-MAC at ~45 ms/MB on a mid-range phone. Native code
flips the comparison: BoringSSL's one-shot GCM is its fast path, while
webcrypto 0.6.1's *streaming* CTR API measured ~10x slower than one-shot GCM
(it copies input byte-by-byte through a Dart iterable) and corrupts chunks
longer than 4096 bytes that are not a multiple of it. One-shot GCM is both
the fastest and the least code.

Details that make the construction sound:

- **The whole header is additional authenticated data**, so tampering with
  the IV, `keyId`, or label is detected by the same tag that covers the
  ciphertext.
- **Nothing decrypted escapes on failure.** BoringSSL's AEAD open verifies
  the tag and refuses to return plaintext when it does not match; a wrong key
  or tampered bytes surface as `DecryptionFailedException`.
- **The working key is derived per model.** HKDF-SHA256 over the caller's
  32-byte master key with info `litert_crypto:enc:v2:<label>` — leaking one
  model's derived key does not unlock the others. The label travels inside
  the envelope, so decryption needs nothing but the master key.
- **The IV is 12 random bytes per encryption** — GCM's 96-bit fast path.
  Random-nonce collision risk grows with the number of messages under one
  key; models are encrypted a handful of times at build time, which is as far
  from that bound as a use case gets.

## Memory hygiene

The plaintext model and the key exist in memory only as long as they must:

- The derived working key is zeroed as soon as it is used. BoringSSL's
  native-side key schedule lives until the key object is garbage collected —
  a copy outside our reach, conceded by the threat model like everything else
  in process memory.
- The loader zeroes the key buffer a `KeyProvider` hands it as soon as the
  model is decrypted — which is why providers must return a fresh copy.
- The decrypted model buffer is zeroed as soon as the `build` callback
  returns; runtimes copy the model into their own memory, so holding the Dart
  buffer would only leave plaintext lying in the heap.
- `InMemoryKeyCache` zeroes entries it drops (expiry, overwrite, `clear()`).

Two limits are inherent and documented rather than fought: the inference
runtime keeps its own copy of the model while it runs, and buffers become
unreachable-then-collected rather than provably erased — Dart offers no
`mlock`/`explicit_bzero` equivalent.

## Build-time encryption: the asset transformer

Since 0.3.0 the primary encrypt path is a Flutter asset transformer: the
flutter tool invokes `dart run litert_crypto --input <tmp> --output <tmp>`
for every asset that lists this package under `transformers:`, and the output
replaces the asset's bytes in the bundle under its original name. Decisions
worth recording:

- **The label is recovered, not taken from the path given.** The tool hands
  the transformer a temp copy named `<basename>-transformOutput<N><ext>`, so
  the CLI strips that suffix to get the asset's own file name — otherwise the
  usual label default would bake a meaningless temp name into the envelope
  (and into key derivation). An explicit `--label` in the transformer args
  overrides.
- **Config discovery is unchanged.** The tool runs transformers from the app's
  project root (`workingDirectory: environment.projectDir.path` in
  flutter_tools), which is exactly where the nearest-`litert_crypto.yaml`
  search already starts. `--config` in the args covers unusual layouts.
- **The config may live in pubspec.yaml.** A top-level `litert_crypto:`
  section is accepted as a *fallback* when no `litert_crypto.yaml` is found
  on the walk — additive, so no existing setup changes meaning. Transformer
  mode shrank the config to two lines that belong next to the asset
  registration anyway, and pubspec edits invalidate the transformed-asset
  cache, which changes to a separate config file cannot. A dedicated file
  wins when both exist; pubspecs without the section are walked past, so a
  monorepo package can inherit a parent's section.
- **`keyparts` exists because the transformer must not write source.**
  Transformers run as parallel per-asset processes in the middle of a build;
  having them regenerate `key_parts_out` under `lib/` would race each other
  and mutate inputs of the very build in progress. Generation stays a
  deliberate CLI step (`keyparts`, or any config-mode `encrypt` run).
- **`key_parts_out` doubles as a build-time drift check.** Config-mode
  `encrypt` kept the generated parts in sync by regenerating them on every
  run; the transformer must not write source (above), so it restores the
  guarantee read-only: before encrypting, it compares the generated file's
  `key-fingerprint` against the key file and fails the build — with a
  `keyparts` hint — when they disagree or the file was never generated. It
  fails rather than warns because the flutter tool surfaces a transformer's
  output only on non-zero exit; a warning would reach no one.
- **Rotation needs a cache nudge.** The tool caches transformed output keyed
  on the asset and the transformer entry — the key file is invisible to it,
  and a cached asset skips the transformer (and the drift check above)
  entirely. Rotating a key therefore pairs with bumping `--key-id` in the
  args (which edits pubspec.yaml and invalidates the cache) or a one-time
  `flutter clean`. Documented in the README rather than fought with a
  cache-busting hack.

## Decided against

- **A `check` CLI failing the build when a plaintext model is registered as
  an asset.** Superseded by the transformer before it was built: an asset
  that lists litert_crypto as its transformer *cannot* reach the bundle in
  plaintext, and prevention beats detection. The residual gap — the
  transformer forgotten entirely — has no build-time answer (the package's
  code never runs for an unregistered asset, and Flutter gives dependencies
  no whole-build hook), so it is met at the two places the package does run:
  the loader recognizes a plaintext TFLite model (`TFL3` identifier) and
  names the situation — bundled unencrypted, releases built this way ship
  the model in the clear — and `flutter test` applies transformers, so any
  test that loads the model catches the omission in CI.
- **A `SecureStorageKeyProvider` in this package.** It would drag
  platform-channel plugins into a package that has none (BoringSSL comes in
  through dart:ffi, not a plugin). `KeyCache` is the seam instead: implement
  it over `flutter_secure_storage` (or your own channel) in your app.
- **Bundling attestation (Play Integrity / App Attest) or license
  verification.** Those are policy, and policy belongs to the app. The package
  provides the injection points (`KeyFetcher`, `CallbackKeyProvider`), not the
  policy.
