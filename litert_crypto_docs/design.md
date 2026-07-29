# litert_crypto — design notes

Internals and the reasoning behind them. For installation and usage, see the
[README](../README.md); for choosing where your key lives, see
[key-management.md](key-management.md).

## The LRTC file format

```
[magic "LRTC" (4B)] [version (1B)] [keyId (2B, BE)] [labelLen (1B)]
[label (labelLen B, UTF-8)] [IV (16B)] [ciphertext] [HMAC-SHA256 tag (32B)]
```

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

## Cipher choice: AES-256-CTR + HMAC-SHA256, encrypt-then-MAC

**Why not AES-GCM?** Measured on a real 10 MB model: GCM took ~580 ms versus
~180 ms for CTR + HMAC in pure Dart, because GHASH gets no hardware
acceleration there. Model decryption sits on the app's load path, so the 3x
difference matters. CTR + HMAC-SHA256 in encrypt-then-MAC composition provides
the same authenticated encryption at a fraction of the cost.

Details that make the composition sound:

- **The tag covers the whole header as well as the ciphertext**, so tampering
  with the IV, `keyId`, or label is detected — not just changes to the payload.
- **The MAC is verified before any decryption happens.** A wrong key or
  tampered bytes never reach the AES step, and the comparison is
  constant-time.
- **Encryption and MAC keys are independent.** Both are derived from the
  caller's 32-byte master key with HKDF-SHA256, using distinct info strings
  (`litert_crypto:enc:v1:<label>` / `litert_crypto:mac:v1:<label>`).
- **The label is mixed into key derivation**, so two models encrypted with the
  same master key get different working keys — leaking one model's derived key
  does not unlock the others. The label travels inside the envelope, so
  decryption needs nothing but the master key.
- **The IV is 16 random bytes per encryption**, and the underlying CTR
  implementation increments the full block big-endian, so keystream reuse
  across models is not a practical concern.

## Memory hygiene

The plaintext model and the key exist in memory only as long as they must:

- Derived working subkeys are destroyed as soon as they are used; the HKDF
  input copy is destroyed after derivation.
- The loader zeroes the key buffer a `KeyProvider` hands it as soon as the
  subkeys are derived — which is why providers must return a fresh copy.
- The decrypted model buffer is zeroed as soon as the `build` callback
  returns; runtimes copy the model into their own memory, so holding the Dart
  buffer would only leave plaintext lying in the heap.
- `InMemoryKeyCache` zeroes entries it drops (expiry, overwrite, `clear()`).

Two limits are inherent and documented rather than fought: the inference
runtime keeps its own copy of the model while it runs, and buffers become
unreachable-then-collected rather than provably erased — Dart offers no
`mlock`/`explicit_bzero` equivalent.

## Decided against

- **A `SecureStorageKeyProvider` in this package.** It would drag platform
  plugins into a pure Dart package. `KeyCache` is the seam instead: implement
  it over `flutter_secure_storage` (or your own channel) in your app.
- **Bundling attestation (Play Integrity / App Attest) or license
  verification.** Those are policy, and policy belongs to the app. The package
  provides the injection points (`KeyFetcher`, `CallbackKeyProvider`), not the
  policy.
