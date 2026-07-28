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
| `RemoteKeyProvider` | Your fetch callback, with retries, single-flight and optional caching | Up to your server's gate | Keeping the key out of the binary entirely |
| `FallbackKeyProvider` | Tries providers in order | — | Combinations like cache → server |

```dart
// Example: pull the key from a signed license file.
final provider = CallbackKeyProvider((context) async {
  final license = await License.loadAndVerify();
  return license.modelKey;
});
```

### Fetching the key from a server

The transport is yours — this package has no HTTP dependency. Bring `package:http`,
dio, or a platform channel; `RemoteKeyProvider` adds the retry, single-flight and
caching plumbing around it.

```dart
final provider = RemoteKeyProvider(
  fetch: (ctx) async {
    final res = await http.get(
      Uri.parse('https://keys.example.com/model-key'
          '?keyId=${ctx.keyId}&label=${ctx.label}'),
      headers: {'Authorization': 'Bearer ${await session.token()}'},
    );
    if (res.statusCode == 403) {
      throw const KeyUnavailableException('not entitled'); // permanent: no retry
    }
    if (res.statusCode != 200) throw StateError('HTTP ${res.statusCode}');
    return decodeKeyBytes(res.bodyBytes); // JSON {"key": base64} / base64 / raw
  },
  cache: InMemoryKeyCache(ttl: const Duration(hours: 12)),
);
```

The callback receives `keyId` and `label`, so one service can serve several models and
key generations. Throw `KeyUnavailableException` for permanent failures (rejected auth,
unknown key) — anything else counts as transient and is retried.

> **A server moves the secret out of your binary; it does not decide who deserves it.**
> That gate is your server's job. On mobile, verifying a Play Integrity / App Attest
> token before responding is what gives this teeth. On desktop there is no equivalent,
> so the gate has to be a credential the user holds (license, account login). Without a
> gate, an attacker just asks your server for the key like any other client.

`KeyCache` is an interface, not a plugin: `InMemoryKeyCache` keeps a fetched key for the
life of the process and never touches disk. To survive restarts, implement `KeyCache` on
top of `flutter_secure_storage` or your own channel — the package stays plugin-free so it
works anywhere `tflite_flutter` does.

## Threat model

| Attack | Defended? |
|---|---|
| Extracting the model by unzipping the bundle (APK / install folder) | ✅ Yes — only ciphertext ships |
| Model tampering (backdoored model injection) | ✅ Detected — HMAC-SHA256 tag over header + ciphertext |
| Copying ciphertext + app to another machine and decrypting offline | Depends on your KeyProvider — Embedded ⚠️ / external key ✅ |
| Memory dump while the app is running | ❌ No — inherent limit of on-device inference (the exposure window is narrowed: key bytes are zeroed once subkeys are derived, and the decrypted buffer is zeroed as soon as the interpreter has copied it) |
| Patching / reverse engineering the decryption logic | ❌ No — combine with `--obfuscate` |

## File format

```
[magic "LRTC" (4B)] [version (1B)] [keyId (2B)] [labelLen (1B)] [label] [IV (16B)] [ciphertext] [HMAC-SHA256 tag (32B)]
```

AES-256-CTR with encrypt-then-MAC (HMAC-SHA256). The tag covers the whole header as well
as the ciphertext, so tampering with the IV, `keyId`, or label is detected. Encryption and
MAC keys are derived from your 32-byte key with HKDF-SHA256, and the MAC is verified before
any decryption happens.

The **label** (defaulting to the source file name) identifies the model and is mixed into
key derivation, so two models encrypted with the same master key get different working
keys — leaking one model's derived key does not unlock the others. It travels inside the
envelope, so decryption needs nothing but the master key.

**Why not AES-GCM?** Measured on a real 10 MB model: GCM took ~580 ms versus ~180 ms for
CTR + HMAC in pure Dart, because GHASH gets no hardware acceleration here. Model
decryption sits on the app's load path, so the 3x difference matters.

`keyId` supports key rotation. Outside Flutter (build scripts, backends) the same format
is available through the Flutter-free entrypoint `package:litert_crypto/codec.dart`.

## Roadmap

- 0.0.1 (current): core format/codec, `EncryptedInterpreter`, Embedded/Callback/Fallback providers, CLI `keygen` / `encrypt`
- Next: `SecureStorageKeyProvider`, `RemoteKeyProvider`, CLI `check` (plaintext-bundle guard), example app
- Under consideration: flutter_litert runtime support, native-accelerated decryption (cryptography_flutter)
