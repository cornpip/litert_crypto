## 0.0.1

Initial draft release.

* LRTC encrypted file format — AES-256-CTR with encrypt-then-MAC (HMAC-SHA256 over header + ciphertext), HKDF-derived subkeys, a per-model label bound into key derivation, and a keyId field for key rotation — plus a pure Dart codec (`package:litert_crypto/codec.dart`)
* Key hygiene: the key handed in by a `KeyProvider` is zeroed once subkeys are derived, and the decrypted model buffer is zeroed after the interpreter copies it
* `EncryptedModel.fromAsset/fromFile/fromBuffer` — runtime-agnostic loader: you pass your runtime's buffer constructor (`Interpreter.fromBuffer`, …) and get its result back. Decryption happens in memory and the plaintext is zeroed once the builder returns. `decryptAsset`/`decryptBuffer` return the bytes when the runtime needs to own the buffer
* No inference-runtime dependency: works with `flutter_litert`, `tflite_flutter`, or any other runtime
* `KeyProvider` interface with `EmbeddedKeyProvider` (XOR part-combining helper), `CallbackKeyProvider`, `FallbackKeyProvider`, and `RemoteKeyProvider` (transport-agnostic fetch callback with retries, single-flight, and a pluggable `KeyCache`; `InMemoryKeyCache` and a `decodeKeyBytes` payload helper included)
* No HTTP or platform-plugin dependencies: the package stays pure Dart and runs wherever tflite_flutter does
* CLI: `dart run litert_crypto keygen | encrypt` (direct arguments or a `litert_crypto.yaml` config). With `key_parts_out`, `encrypt` also generates the Dart source for `EmbeddedKeyProvider`, so the embedded key cannot drift from the key the models were encrypted with; it rewrites that file only when the key changed
* Exception hierarchy: `InvalidFormatException` / `KeyUnavailableException` / `DecryptionFailedException`
