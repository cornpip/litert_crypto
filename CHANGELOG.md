# Changelog

## 0.2.0

* Decryption runs on a worker isolate by default (`inIsolate`, on every loader
  entry point). A 68 MB model takes seconds to decrypt; run inline that is
  seconds of a frozen UI. The ciphertext travels as `TransferableTypedData` and
  the plaintext returns through `Isolate.run`, so neither crossing copies the
  model. **This changes default behaviour** — pass `inIsolate: false` to keep
  decryption on the calling isolate.
* Decryption no longer joins the header and ciphertext into one buffer to
  compute the MAC — it hashes them incrementally. That copy was the size of the
  whole model, so a large model now needs one buffer less at peak.
* `decryptEnvelope` allocates exactly one buffer and converts the ciphertext
  inside it, instead of taking whatever the cipher allocated and sometimes
  copying that again.
* New `LrtcCodec.decryptInPlace` / `decryptBufferInPlace`: decrypt a buffer you
  own with no allocation at all. Not for assets — asset bundles hand out
  read-only buffers on Android.
* Decryption yields to the event loop between chunks, so a multi-second
  decryption no longer holds the isolate in one uninterrupted block.

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
