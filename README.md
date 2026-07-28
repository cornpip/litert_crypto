# litert_crypto

Encrypt and load **LiteRT (TensorFlow Lite / TFLite)** models — a build-time encryption CLI plus an in-memory decryption loader with pluggable key providers.

> **This package does not guarantee protection.** It provides encryption tooling and a key
> injection point (`KeyProvider`); the actual protection strength is determined by how you
> manage your keys. Read the [threat model](#threat-model) first.

## The problem

A `.tflite` model bundled in a Flutter app can be **extracted verbatim by unzipping** the
APK / IPA / desktop install folder. This package encrypts models at build time and decrypts
them **in memory only** at runtime before handing them to an `Interpreter`. The plaintext
model never touches the disk.

## Usage

### 1. Generate a key and encrypt models (build time)

```bash
dart run litert_crypto keygen                 # writes .secrets/model.key (gitignore it!)
dart run litert_crypto encrypt \
  --key .secrets/model.key \
  --in models_src/model.tflite \
  --out assets/tflite_model/model.tflite.enc
```

For multiple models, use `litert_crypto.yaml`:

```yaml
litert_crypto:
  key_file: .secrets/model.key
  models:
    - src: models_src/yolo.tflite
      out: assets/tflite_model/yolo.tflite.enc
```

```bash
dart run litert_crypto encrypt    # batch mode using the config file
```

Keep plaintext originals (`models_src/`) outside your assets and out of version control.
Register only the `.enc` files as Flutter assets.

### 2. Load at runtime — drop-in replacement for `Interpreter.fromAsset()`

```dart
import 'package:litert_crypto/litert_crypto.dart';

// Before: Interpreter.fromAsset('assets/tflite_model/model.tflite')
final interpreter = await EncryptedInterpreter.fromAsset(
  'assets/tflite_model/model.tflite.enc',
  keyProvider: EmbeddedKeyProvider.fromParts([keyPartA, keyPartB]),
);
// Returns the same Interpreter type — your inference code stays unchanged.
```

## KeyProvider — the key source is your policy

| Provider | Key source | Strength | Use case |
|---|---|---|---|
| `EmbeddedKeyProvider` | Embedded in the app (XOR part-combining helper) | Low | Minimum defense — only stops unzip extraction |
| `CallbackKeyProvider` | Your callback (license file, custom storage, ...) | Up to you | App-specific policies such as license binding |
| `FallbackKeyProvider` | Tries providers in order | — | Combinations like cache → server |
| (roadmap) SecureStorage / Remote | Keystore / Keychain / server | High | Planned |

```dart
// Example: pull the key from a signed license file.
final provider = CallbackKeyProvider((context) async {
  final license = await License.loadAndVerify();
  return license.modelKey;
});
```

## Threat model

| Attack | Defended? |
|---|---|
| Extracting the model by unzipping the bundle (APK / install folder) | ✅ Yes — only ciphertext ships |
| Model tampering (backdoored model injection) | ✅ Detected — HMAC-SHA256 tag over header + ciphertext |
| Copying ciphertext + app to another machine and decrypting offline | Depends on your KeyProvider — Embedded ⚠️ / external key ✅ |
| Memory dump while the app is running | ❌ No — inherent limit of on-device inference |
| Patching / reverse engineering the decryption logic | ❌ No — combine with `--obfuscate` |

## File format

```
[magic "LRTC" (4B)] [version (1B)] [keyId (2B)] [IV (16B)] [ciphertext] [HMAC-SHA256 tag (32B)]
```

AES-256-CTR with encrypt-then-MAC (HMAC-SHA256). The tag covers the header as well as the
ciphertext, so tampering with the IV or `keyId` is detected. Encryption and MAC keys are
derived from your 32-byte key with HKDF-SHA256, and the MAC is verified before any
decryption happens.

**Why not AES-GCM?** Measured on a real 10 MB model: GCM took ~580 ms versus ~180 ms for
CTR + HMAC in pure Dart, because GHASH gets no hardware acceleration here. Model
decryption sits on the app's load path, so the 3x difference matters.

`keyId` supports key rotation. Outside Flutter (build scripts, backends) the same format
is available through the Flutter-free entrypoint `package:litert_crypto/codec.dart`.

## Roadmap

- 0.0.1 (current): core format/codec, `EncryptedInterpreter`, Embedded/Callback/Fallback providers, CLI `keygen` / `encrypt`
- Next: `SecureStorageKeyProvider`, `RemoteKeyProvider`, CLI `check` (plaintext-bundle guard), example app
- Under consideration: flutter_litert runtime support, native-accelerated decryption (cryptography_flutter)
