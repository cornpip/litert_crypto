// litert_crypto usage example.
//
// Build-time preparation:
//   dart run litert_crypto keygen
//   dart run litert_crypto encrypt --key .secrets/model.key \
//     --in models_src/model.tflite --out assets/tflite_model/model.tflite.enc
//   (register only the .enc file as a Flutter asset)

import 'dart:typed_data';

import 'package:litert_crypto/litert_crypto.dart';
import 'package:tflite_flutter/tflite_flutter.dart';

Future<Interpreter> loadModel() async {
  // Demo key parts — in a real app, pick the KeyProvider that matches your
  // distribution model (see the KeyProvider table in the README).
  final partA = Uint8List.fromList(List.generate(32, (i) => i * 7 & 0xFF));
  final partB = Uint8List.fromList(List.generate(32, (i) => i * 13 & 0xFF));

  return EncryptedInterpreter.fromAsset(
    'assets/tflite_model/model.tflite.enc',
    keyProvider: EmbeddedKeyProvider.fromParts([partA, partB]),
  );
}

Future<void> main() async {
  final interpreter = await loadModel();
  // From here it is plain tflite_flutter: interpreter.run(input, output);
  interpreter.close();
}
