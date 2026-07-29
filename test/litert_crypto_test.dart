import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:litert_crypto/codec.dart';
import 'package:litert_crypto/src/decrypt_flow.dart';
import 'package:litert_crypto/src/isolate_decrypt.dart';
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
      // flip the first ciphertext byte (header is fixed-size for an empty label)
      encrypted[LrtcEnvelope.fixedHeaderLength + LrtcEnvelope.ivLength] ^= 0xFF;
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

  group('per-model key separation (label)', () {
    test('label round-trips through the envelope', () async {
      final encrypted =
          await LrtcCodec.encrypt(_payload(), _key(), label: 'yolo.tflite');
      expect(LrtcEnvelope.parse(encrypted).label, 'yolo.tflite');
      expect(await LrtcCodec.decrypt(encrypted, _key()), equals(_payload()));
    });

    test('same key + different labels produce different working keys',
        () async {
      // Re-labelling one model's envelope must not decrypt under the derived
      // key of another: the label is bound into HKDF and authenticated.
      final a = await LrtcCodec.encrypt(_payload(), _key(), label: 'model-a');
      final parsed = LrtcEnvelope.parse(a);
      final forged = LrtcEnvelope(
        version: parsed.version,
        keyId: parsed.keyId,
        label: 'model-b',
        header: LrtcEnvelope.buildHeader(
          version: parsed.version,
          keyId: parsed.keyId,
          label: 'model-b',
          iv: parsed.iv,
        ),
        iv: parsed.iv,
        sealed: parsed.sealed,
      ).serialize();

      expect(
        () => LrtcCodec.decrypt(forged, _key()),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('an over-long label is rejected', () async {
      expect(
        () => LrtcCodec.encrypt(_payload(), _key(), label: 'x' * 256),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('key hygiene', () {
    test('the codec does not mutate the caller\'s key buffer', () async {
      final key = _key();
      final encrypted = await LrtcCodec.encrypt(_payload(), key);
      expect(key, equals(_key()), reason: 'key must be reusable');
      expect(await LrtcCodec.decrypt(encrypted, key), equals(_payload()));
      expect(key, equals(_key()));
    });

    test('decryptWithProvider zeroes the key it received', () async {
      Uint8List? handedOut;
      final provider = CallbackKeyProvider((_) async {
        handedOut = _key();
        return handedOut!;
      });
      final encrypted = await LrtcCodec.encrypt(_payload(), _key());

      final plain = await decryptWithProvider(
        LrtcEnvelope.parse(encrypted),
        provider,
      );

      expect(plain, equals(_payload()));
      expect(handedOut!.every((b) => b == 0), isTrue,
          reason: 'the loader must clear the key after use');
    });

    test('EmbeddedKeyProvider survives repeated use (returns copies)',
        () async {
      final provider = EmbeddedKeyProvider(_key());
      const context = KeyContext(keyId: 0);

      final encrypted =
          await LrtcCodec.encrypt(_payload(), await provider.getKey(context));
      final decrypted =
          await LrtcCodec.decrypt(encrypted, await provider.getKey(context));

      expect(decrypted, equals(_payload()));
    });

    test('wipe() zeroes a buffer', () {
      final bytes = _payload(64);
      LrtcCodec.wipe(bytes);
      expect(bytes.every((b) => b == 0), isTrue);
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

    test('FallbackKeyProvider falls through on unexpected exceptions too',
        () async {
      // A transient I/O failure (not a KeyUnavailableException) in an early
      // provider must not block a later provider that would succeed.
      final failing = CallbackKeyProvider(
        (_) async => throw const FormatException('corrupt local cache'),
      );
      final provider =
          FallbackKeyProvider([failing, EmbeddedKeyProvider(_key())]);
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

  group('isolate decryption', () {
    test('returns the same plaintext as the inline path', () async {
      final plain = _payload(5 * 1024 * 1024 + 77);
      final encrypted = await LrtcCodec.encrypt(plain, _key(), label: 'iso');

      final onIsolate = await decryptOnIsolate(encrypted, _key());

      expect(onIsolate, equals(plain));
    });

    test('leaves the caller buffer and key intact', () async {
      final encrypted = await LrtcCodec.encrypt(_payload(), _key());
      final untouched = Uint8List.fromList(encrypted);
      final key = _key();

      await decryptOnIsolate(encrypted, key);

      expect(encrypted, equals(untouched));
      expect(key, equals(_key()));
    });

    test('a wrong key fails there too', () async {
      final encrypted = await LrtcCodec.encrypt(_payload(), _key());
      await expectLater(
        decryptOnIsolate(encrypted, _key(11)),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('the caller isolate keeps running while it works', () async {
      // 60 MB: seconds of AES. If it ran inline, the ticks below would stall.
      final encrypted =
          await LrtcCodec.encrypt(_payload(60 * 1024 * 1024), _key());

      var ticks = 0;
      final timer =
          Timer.periodic(const Duration(milliseconds: 10), (_) => ticks++);
      final watch = Stopwatch()..start();
      await decryptOnIsolate(encrypted, _key());
      watch.stop();
      timer.cancel();

      // Anything close to the theoretical tick count means the event loop was
      // free; an inline run would have blocked nearly all of them.
      final expected = watch.elapsedMilliseconds ~/ 10;
      expect(ticks, greaterThan(expected ~/ 2),
          reason: 'only $ticks of ~$expected ticks fired — the caller stalled');
    });
  });

  group('buffer discipline', () {
    test('a large, block-unaligned model round-trips', () async {
      final plain = _payload(9 * 1024 * 1024 + 12345);
      final encrypted = await LrtcCodec.encrypt(plain, _key(), label: 'big');
      expect(await LrtcCodec.decrypt(encrypted, _key()), equals(plain));
    });

    test('decryption reads a read-only buffer without touching it', () async {
      // Asset bundles hand out read-only buffers on Android; decryption must
      // never attempt to write into its input.
      final encrypted = await LrtcCodec.encrypt(_payload(), _key());
      final readOnly = encrypted.asUnmodifiableView();
      expect(await LrtcCodec.decrypt(readOnly, _key()), equals(_payload()));
    });
  });
}
