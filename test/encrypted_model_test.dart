import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:litert_crypto/codec.dart';
import 'package:litert_crypto/src/encrypted_model.dart';
import 'package:litert_crypto/src/key_provider/embedded_key_provider.dart';
import 'package:litert_crypto/src/key_provider/key_provider.dart';

Uint8List _key([int seed = 7]) =>
    Uint8List.fromList(List.generate(32, (i) => (i * seed + 3) & 0xFF));

Uint8List _model([int length = 2048]) =>
    Uint8List.fromList(List.generate(length, (i) => (i * 31 + 17) & 0xFF));

Future<Uint8List> _encrypted({String label = 'model.tflite'}) =>
    LrtcCodec.encrypt(_model(), _key(), label: label);

void main() {
  group('EncryptedModel.fromBuffer', () {
    test('hands the decrypted model to the builder', () async {
      Uint8List? seen;
      final result = await EncryptedModel.fromBuffer(
        await _encrypted(),
        keyProvider: EmbeddedKeyProvider(_key()),
        build: (bytes) {
          // Runtimes copy the buffer; mimic that so the assertion survives the
          // wipe that follows.
          seen = Uint8List.fromList(bytes);
          return 'built';
        },
      );

      expect(result, 'built');
      expect(seen, equals(_model()));
    });

    test('zeroes the plaintext once the builder returns', () async {
      late Uint8List handedOut;
      await EncryptedModel.fromBuffer(
        await _encrypted(),
        keyProvider: EmbeddedKeyProvider(_key()),
        build: (bytes) {
          handedOut = bytes;
          return null;
        },
      );

      expect(handedOut.every((b) => b == 0), isTrue,
          reason: 'plaintext must not linger after the build call');
    });

    test('supports an async builder', () async {
      final result = await EncryptedModel.fromBuffer(
        await _encrypted(),
        keyProvider: EmbeddedKeyProvider(_key()),
        build: (bytes) async {
          await Future<void>.delayed(Duration.zero);
          return bytes.length;
        },
      );

      expect(result, _model().length);
    });

    test('wipes the plaintext even when the builder throws', () async {
      late Uint8List handedOut;

      await expectLater(
        EncryptedModel.fromBuffer<void>(
          await _encrypted(),
          keyProvider: EmbeddedKeyProvider(_key()),
          build: (bytes) {
            handedOut = bytes;
            throw StateError('runtime rejected the model');
          },
        ),
        throwsA(isA<StateError>()),
      );

      expect(handedOut.every((b) => b == 0), isTrue);
    });

    test('a wrong key fails before the builder runs', () async {
      var built = false;

      await expectLater(
        EncryptedModel.fromBuffer<void>(
          await _encrypted(),
          keyProvider: EmbeddedKeyProvider(_key(11)),
          build: (_) {
            built = true;
          },
        ),
        throwsA(isA<DecryptionFailedException>()),
      );

      expect(built, isFalse);
    });

    test('plaintext input is rejected as an invalid envelope', () async {
      await expectLater(
        EncryptedModel.fromBuffer<void>(
          _model(),
          keyProvider: EmbeddedKeyProvider(_key()),
          build: (_) {},
        ),
        throwsA(isA<InvalidFormatException>()),
      );
    });

    test('passes the envelope label to the key provider', () async {
      String? seenLabel;
      await EncryptedModel.fromBuffer(
        await _encrypted(label: 'yolo.tflite'),
        keyProvider: CallbackProbe((ctx) {
          seenLabel = ctx.label;
          return _key();
        }),
        build: (_) => null,
      );

      expect(seenLabel, 'yolo.tflite');
    });
  });

  group('EncryptedModel.decryptBuffer', () {
    test('returns plaintext the caller owns (not wiped)', () async {
      final plain = await EncryptedModel.decryptBuffer(
        await _encrypted(),
        keyProvider: EmbeddedKeyProvider(_key()),
      );

      expect(plain, equals(_model()));
    });
  });
}

/// Minimal provider that records the context it was called with.
class CallbackProbe implements KeyProvider {
  CallbackProbe(this._fn);

  final Uint8List Function(KeyContext context) _fn;

  @override
  Future<Uint8List> getKey(KeyContext context) async => _fn(context);
}
