# litert_crypto example

Transformer-mode round trip: the committed model asset
(`assets/tflite_model/demo_model.bin`, a stand-in for a real `.tflite`) is
plaintext, the build encrypts it into the bundle, and the app decrypts it
**in memory only**.

```bash
flutter run -d windows    # or: -d <android-device>
```

The wiring is all in `pubspec.yaml` — the `litert_crypto:` config section and
the transformer on the asset. `flutter test` runs a smoke test over the same
pipeline.

> **The demo key (`.secrets/`) is deliberately committed** — its XOR parts are
> committed in `lib/model_master_key.dart` anyway, and the build needs the key
> file even on a fresh clone. A real app gitignores its key.
