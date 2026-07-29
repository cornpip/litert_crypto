# Changelog

## 0.2.0

The crypto engine is now native BoringSSL (`package:webcrypto`, dart:ffi)
and the format is AES-256-GCM. Decryption is dramatically faster: about
1.2 ms/MB on an AES-NI desktop, so a 72 MB model decrypts in 87 ms. This is
a clean break from 0.1.0 — re-encrypting your models is the whole migration
(details under Breaking).

**Breaking:**

* **LRTC format version 2** — AES-256-GCM (12-byte IV, 16-byte tag, header as
  additional authenticated data) replaces AES-CTR + HMAC-SHA256. Files written
  by 0.1.0 are refused with a re-encrypt hint; re-running
  `dart run litert_crypto encrypt` is the whole migration.
* `LrtcCodec.decryptInPlace` / `decryptBufferInPlace` /
  `decryptWithProviderInPlace` are gone — GCM verifies and decrypts in one
  native call, which has no in-place variant. `LrtcEnvelope`'s
  `cipherText`/`tag` fields became `sealed` (ciphertext ‖ tag).
* SDK floors rose to Dart 3.10 / Flutter 3.38 (webcrypto builds BoringSSL via
  Dart hooks).
* Host builds (`flutter test`, CLI on a plain Dart VM) compile BoringSSL and
  need `cmake` + a C compiler, plus NASM on Windows x64. App builds compile it
  through Gradle/NDK/Xcode with nothing to configure.

**Also:**

* Decryption now runs on a worker isolate by default, so the calling isolate
  keeps rendering through it. Pass `inIsolate: false` (available on every
  loader entry point) to keep it inline.

## 0.1.0

Initial release.

* LRTC encrypted model format: AES-256-CTR with encrypt-then-MAC
  (HMAC-SHA256), HKDF-derived per-model subkeys, `keyId` for key rotation —
  plus a Flutter-free codec entrypoint (`package:litert_crypto/codec.dart`)
* `EncryptedModel.fromAsset/fromFile/fromBuffer` loader — decrypts in memory
  only, zeroes keys and plaintext after use, no inference-runtime dependency
* Key providers: `EmbeddedKeyProvider` (XOR parts), `CallbackKeyProvider`,
  `RemoteKeyProvider` (retries, single-flight, pluggable `KeyCache`),
  `FallbackKeyProvider`
* CLI: `dart run litert_crypto init | keygen | encrypt`, including generated
  `EmbeddedKeyProvider` source kept in sync with the key (`key_parts_out`)
