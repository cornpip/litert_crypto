# litert_crypto example

A runnable app demonstrating the full litert_crypto round trip: a bundled
encrypted asset is decrypted **in memory only** and handed to a stand-in for
your inference runtime.

```bash
flutter run -d windows    # or: -d <android-device>
```

Android and Windows runners are checked in; the Dart code is identical on every
platform, so add another runner with e.g. `flutter create --platforms=macos .`.

## How the committed artifacts were made

From this directory, using the package's own CLI (config in
`litert_crypto.yaml`):

```bash
dart run litert_crypto keygen    # .secrets/model_master.key (gitignored)
dart run litert_crypto encrypt   # assets/tflite_model/demo_model.bin.enc
                                 # + generated lib/model_master_key.dart
```

`models_src/demo_model.bin` (4 KB of random bytes) stands in for a real
`.tflite` — the codec encrypts any file. Only the `.enc` output is registered
as a Flutter asset; the plaintext source never ships.

**The demo key is disposable.** Its parts are committed in
`lib/model_master_key.dart` because that is how `EmbeddedKeyProvider` works —
which also demonstrates the caveat from the package README: anyone with this
repository can recover the demo key. For your own app, treat the repository as
inside your trust boundary or use a key provider whose key does not ship.

`flutter test` runs a smoke test proving the committed ciphertext and the
generated key source still match.
