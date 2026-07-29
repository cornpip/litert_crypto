// litert_crypto runnable example.
//
// The committed artifacts were produced by the package's own CLI, run from
// this directory:
//   dart run litert_crypto keygen    # wrote .secrets/model_master.key (not committed)
//   dart run litert_crypto encrypt   # wrote assets/tflite_model/demo_model.bin.enc
//                                    # and generated lib/model_master_key.dart
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
    'assets/tflite_model/demo_model.bin.enc',
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
                'only the .enc ciphertext is bundled in this app.',
                textAlign: TextAlign.center,
              );
            },
          ),
        ),
      ),
    );
  }
}
