import 'package:flutter_test/flutter_test.dart';
import 'package:litert_crypto_example/main.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('the committed .enc asset decrypts with the generated key parts',
      () async {
    // End-to-end over the real committed artifacts: the bundled ciphertext,
    // the generated key source, and the loader. Fails if they ever drift.
    final model = await loadModel();
    expect(model.byteCount, 4096); // size of models_src/demo_model.bin
  });
}
