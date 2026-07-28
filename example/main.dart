// litert_crypto usage example.
//
// Build-time preparation:
//   dart run litert_crypto keygen
//   dart run litert_crypto encrypt --key .secrets/model.key \
//     --in models_src/model.tflite --out assets/tflite_model/model.tflite.enc
//   (register only the .enc file as a Flutter asset)

import 'dart:typed_data';

import 'package:litert_crypto/litert_crypto.dart';

/// Stands in for your inference runtime's model type. In a real app this is an
/// `Interpreter` from `flutter_litert` or `tflite_flutter`, and [build] below
/// becomes `Interpreter.fromBuffer` — this package depends on no runtime, so
/// you decide which one.
class FakeModel {
  FakeModel(this.byteCount);

  final int byteCount;
}

Future<FakeModel> loadModel() async {
  // Demo key parts — in a real app, pick the KeyProvider that matches your
  // distribution model (see the KeyProvider table in the README).
  final partA = Uint8List.fromList(List.generate(32, (i) => i * 7 & 0xFF));
  final partB = Uint8List.fromList(List.generate(32, (i) => i * 13 & 0xFF));

  return EncryptedModel.fromAsset(
    'assets/tflite_model/model.tflite.enc',
    keyProvider: EmbeddedKeyProvider.fromParts([partA, partB]),
    // Real usage: build: Interpreter.fromBuffer
    build: (bytes) => FakeModel(bytes.length),
  );
}

/// Pulling the key from a signed license file instead of the binary.
KeyProvider licenseBackedKey() {
  return CallbackKeyProvider((context) async {
    // final license = await License.loadAndVerify();
    // return license.modelKey;
    throw const KeyUnavailableException('wire up your license loader');
  });
}

Future<void> main() async {
  final model = await loadModel();
  // ignore: avoid_print
  print('decrypted model: ${model.byteCount} bytes');
}
