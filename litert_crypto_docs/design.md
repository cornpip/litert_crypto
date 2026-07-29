# litert_crypto — design notes

Internals and the reasoning behind them. For installation and usage, see the
[README](../README.md); for choosing where your key lives, see
[key-management.md](key-management.md).

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
reads the label, which is why the CLI defaults it to the *output* file name:
that name already appears in the shipped bundle, so it gives nothing away that
unzipping would not. Naming your output generically is therefore enough; pass an
explicit `label:` only if you want it to differ from the file name.

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

## Decided against

- **A `SecureStorageKeyProvider` in this package.** It would drag
  platform-channel plugins into a package that has none (BoringSSL comes in
  through dart:ffi, not a plugin). `KeyCache` is the seam instead: implement
  it over `flutter_secure_storage` (or your own channel) in your app.
- **Bundling attestation (Play Integrity / App Attest) or license
  verification.** Those are policy, and policy belongs to the app. The package
  provides the injection points (`KeyFetcher`, `CallbackKeyProvider`), not the
  policy.
