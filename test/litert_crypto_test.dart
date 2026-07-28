import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:litert_crypto/codec.dart';
import 'package:litert_crypto/src/key_provider/callback_key_provider.dart';
import 'package:litert_crypto/src/key_provider/embedded_key_provider.dart';
import 'package:litert_crypto/src/key_provider/fallback_key_provider.dart';
import 'package:litert_crypto/src/key_provider/key_provider.dart';

Uint8List _key([int seed = 7]) =>
    Uint8List.fromList(List.generate(32, (i) => (i * seed + 3) & 0xFF));

Uint8List _payload([int length = 4096]) =>
    Uint8List.fromList(List.generate(length, (i) => (i * 31 + 17) & 0xFF));

void main() {
  group('LrtcCodec roundtrip', () {
    test('encrypt -> decrypt returns original bytes', () async {
      final plain = _payload();
      final encrypted = await LrtcCodec.encrypt(plain, _key(), keyId: 42);
      expect(encrypted, isNot(equals(plain)));

      final decrypted = await LrtcCodec.decrypt(encrypted, _key());
      expect(decrypted, equals(plain));
    });

    test('keyId survives the envelope', () async {
      final encrypted = await LrtcCodec.encrypt(_payload(), _key(), keyId: 1337);
      final envelope = LrtcEnvelope.parse(encrypted);
      expect(envelope.keyId, 1337);
      expect(envelope.version, LrtcEnvelope.currentVersion);
    });

    test('wrong key throws DecryptionFailedException', () async {
      final encrypted = await LrtcCodec.encrypt(_payload(), _key());
      expect(
        () => LrtcCodec.decrypt(encrypted, _key(11)),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('tampered ciphertext throws DecryptionFailedException', () async {
      final encrypted = await LrtcCodec.encrypt(_payload(), _key());
      encrypted[LrtcEnvelope.headerLength] ^= 0xFF; // flip first ciphertext byte
      expect(
        () => LrtcCodec.decrypt(encrypted, _key()),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('tampered header (IV) is detected — encrypt-then-MAC covers it',
        () async {
      final encrypted = await LrtcCodec.encrypt(_payload(), _key());
      encrypted[10] ^= 0xFF; // flip a byte inside the IV
      expect(
        () => LrtcCodec.decrypt(encrypted, _key()),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('tampered keyId is detected', () async {
      final encrypted = await LrtcCodec.encrypt(_payload(), _key(), keyId: 1);
      encrypted[6] = 2; // keyId 1 -> 2
      expect(
        () => LrtcCodec.decrypt(encrypted, _key()),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('non-32-byte key throws KeyUnavailableException', () async {
      expect(
        () => LrtcCodec.encrypt(_payload(), Uint8List(16)),
        throwsA(isA<KeyUnavailableException>()),
      );
    });
  });

  group('LrtcEnvelope.parse', () {
    test('plaintext input throws InvalidFormatException', () {
      expect(
        () => LrtcEnvelope.parse(_payload()),
        throwsA(isA<InvalidFormatException>()),
      );
    });

    test('too-short input throws InvalidFormatException', () {
      expect(
        () => LrtcEnvelope.parse(Uint8List(10)),
        throwsA(isA<InvalidFormatException>()),
      );
    });

    test('unsupported version throws InvalidFormatException', () async {
      final encrypted = await LrtcCodec.encrypt(_payload(), _key());
      encrypted[4] = 99; // corrupt the version byte
      expect(
        () => LrtcEnvelope.parse(encrypted),
        throwsA(isA<InvalidFormatException>()),
      );
    });
  });

  group('KeyProviders', () {
    const context = KeyContext(keyId: 0);

    test('EmbeddedKeyProvider returns the key', () async {
      final provider = EmbeddedKeyProvider(_key());
      expect(await provider.getKey(context), equals(_key()));
    });

    test('EmbeddedKeyProvider.fromParts XOR-combines parts', () async {
      final partA = _key(3);
      final partB = _key(5);
      final expected = Uint8List.fromList(
        List.generate(32, (i) => partA[i] ^ partB[i]),
      );
      final provider = EmbeddedKeyProvider.fromParts([partA, partB]);
      expect(await provider.getKey(context), equals(expected));
    });

    test('CallbackKeyProvider delegates and receives context', () async {
      KeyContext? seen;
      final provider = CallbackKeyProvider((ctx) async {
        seen = ctx;
        return _key();
      });
      const ctx = KeyContext(keyId: 7, source: 'assets/m.enc');
      expect(await provider.getKey(ctx), equals(_key()));
      expect(seen?.keyId, 7);
      expect(seen?.source, 'assets/m.enc');
    });

    test('FallbackKeyProvider falls through to next provider', () async {
      final failing = CallbackKeyProvider(
        (_) async => throw const KeyUnavailableException('nope'),
      );
      final provider = FallbackKeyProvider([failing, EmbeddedKeyProvider(_key())]);
      expect(await provider.getKey(context), equals(_key()));
    });

    test('FallbackKeyProvider throws when all fail', () async {
      final failing = CallbackKeyProvider(
        (_) async => throw const KeyUnavailableException('nope'),
      );
      expect(
        () => FallbackKeyProvider([failing]).getKey(context),
        throwsA(isA<KeyUnavailableException>()),
      );
    });
  });
}
