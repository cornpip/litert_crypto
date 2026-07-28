## 0.0.1

Initial draft release.

* LRTC encrypted file format — AES-256-CTR with encrypt-then-MAC (HMAC-SHA256 over header + ciphertext), HKDF-derived subkeys, and a keyId field for key rotation — plus a pure Dart codec (`package:litert_crypto/codec.dart`)
* `EncryptedInterpreter.fromAsset/fromFile/fromBuffer` — drop-in loader returning a tflite_flutter `Interpreter` (in-memory decryption, plaintext never written to disk)
* `KeyProvider` interface with `EmbeddedKeyProvider` (XOR part-combining helper), `CallbackKeyProvider`, and `FallbackKeyProvider`
* CLI: `dart run litert_crypto keygen | encrypt` (direct arguments or a `litert_crypto.yaml` config)
* Exception hierarchy: `InvalidFormatException` / `KeyUnavailableException` / `DecryptionFailedException`
