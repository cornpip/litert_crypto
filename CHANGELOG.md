# Changelog

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
