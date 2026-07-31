// litert_crypto runnable example — transformer mode.
//
// assets/tflite_model/demo_model.bin is registered as a plaintext asset, but
// pubspec.yaml lists litert_crypto as its transformer, so `flutter build`
// encrypts it on the way into the bundle: only ciphertext ships. The one-time
// setup was:
//   dart run litert_crypto keygen     # wrote .secrets/model_master.key
//   dart run litert_crypto keyparts   # generated lib/model_master_key.dart
//
// (This demo commits its key file — its XOR parts are committed in
// lib/model_master_key.dart anyway, so the demo hides nothing, and committing
// it keeps the example buildable from a fresh clone. A real app gitignores
// the key.)
//
// demo_model.bin stands in for a real .tflite — the codec encrypts any file,
// and this app proves the round trip: only ciphertext is bundled as an asset,
// and the plaintext exists in memory alone.

import 'package:flutter/material.dart';
import 'package:litert_crypto/litert_crypto.dart';

import 'model_master_key.dart';

/// Stands in for your inference runtime's model type. In a real app this is an
/// `Interpreter` from `flutter_litert` or `tflite_flutter`, and the `build`
/// callback below becomes `Interpreter.fromBuffer` — this package depends on
/// no runtime, so you decide which one.
class FakeModel {
  FakeModel(this.byteCount);

  final int byteCount;
}

Future<FakeModel> loadModel() {
  return EncryptedModel.fromAsset(
    // The asset keeps its plaintext name — the transformer swapped its
    // contents for LRTC ciphertext when the bundle was built.
    'assets/tflite_model/demo_model.bin',
    // buildModelKeyProvider() comes from the generated lib/model_master_key.dart.
    // An embedded key is the weakest tier — pick the KeyProvider matching your
    // distribution model (see the KeyProvider table in the README).
    keyProvider: buildModelKeyProvider(),
    // Real usage: build: Interpreter.fromBuffer
    build: (bytes) => FakeModel(bytes.length),
  );
}

void main() => runApp(const ExampleApp());

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'litert_crypto example',
      home: Scaffold(
        appBar: AppBar(title: const Text('litert_crypto example')),
        body: Center(
          child: FutureBuilder<FakeModel>(
            future: loadModel(),
            builder: (context, snapshot) {
              if (snapshot.hasError) {
                return Text('Decryption failed: ${snapshot.error}');
              }
              if (!snapshot.hasData) {
                return const CircularProgressIndicator();
              }
              return Text(
                'Decrypted ${snapshot.data!.byteCount} bytes in memory —\n'
                'the build bundled only ciphertext in this app.',
                textAlign: TextAlign.center,
              );
            },
          ),
        ),
      ),
    );
  }
}
