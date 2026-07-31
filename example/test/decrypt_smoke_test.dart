import 'package:flutter_test/flutter_test.dart';
import 'package:litert_crypto_example/main.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('the transformed asset decrypts with the generated key parts',
      () async {
    // End-to-end over the real build pipeline: the transformer encrypts the
    // asset on the way into the (test) bundle, and the loader decrypts it
    // with the committed generated key source. Fails if they ever drift.
    final model = await loadModel();
    expect(model.byteCount, 4096); // size of assets/tflite_model/demo_model.bin
  });
}
