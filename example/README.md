# litert_crypto example

CLI round trip: `models_src/demo_model.bin` (a stand-in for a real
`.tflite`) is encrypted by the CLI into the committed
`assets/tflite_model/demo_model.bin.enc`, and the app decrypts it
**in memory only**.

```bash
flutter run -d windows    # or: -d <android-device>
```

The config is the `litert_crypto:` section of `pubspec.yaml`. The committed
artifacts were produced from this directory with:

```bash
dart run litert_crypto keygen    # .secrets/model_master.key (gitignored)
dart run litert_crypto encrypt   # assets/tflite_model/demo_model.bin.enc
                                 # + generated lib/model_master_key.dart
```

`flutter test` runs a smoke test proving the committed ciphertext and the
generated key source still match.

> **The demo key is disposable.** Its XOR parts are committed in
> `lib/model_master_key.dart` — that is how `EmbeddedKeyProvider` works —
> so anyone with this repository can recover it. For your own app, treat
> the repository as inside your trust boundary or use a key provider whose
> key does not ship.
