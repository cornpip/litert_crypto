import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:litert_crypto/codec.dart';
import 'package:litert_crypto/src/key_provider/key_cache.dart';
import 'package:litert_crypto/src/key_provider/key_provider.dart';
import 'package:litert_crypto/src/key_provider/remote_key_provider.dart';

Uint8List _key([int seed = 7]) =>
    Uint8List.fromList(List.generate(32, (i) => (i * seed + 3) & 0xFF));

const _context = KeyContext(keyId: 3, label: 'yolo.tflite');

void main() {
  group('RemoteKeyProvider', () {
    test('returns what the fetcher produced, with the request context',
        () async {
      KeyContext? seen;
      final provider = RemoteKeyProvider(
        fetch: (ctx) async {
          seen = ctx;
          return _key();
        },
      );

      expect(await provider.getKey(_context), equals(_key()));
      expect(seen?.keyId, 3);
      expect(seen?.label, 'yolo.tflite');
    });

    test('retries transient failures, then succeeds', () async {
      var calls = 0;
      final provider = RemoteKeyProvider(
        retryDelay: Duration.zero,
        fetch: (_) async {
          calls++;
          if (calls < 3) throw StateError('HTTP 503');
          return _key();
        },
      );

      expect(await provider.getKey(_context), equals(_key()));
      expect(calls, 3);
    });

    test('does not retry a permanent failure', () async {
      var calls = 0;
      final provider = RemoteKeyProvider(
        retryDelay: Duration.zero,
        fetch: (_) async {
          calls++;
          throw const KeyUnavailableException('not entitled');
        },
      );

      await expectLater(
        provider.getKey(_context),
        throwsA(isA<KeyUnavailableException>()),
      );
      expect(calls, 1, reason: 'retrying will not fix authorization');
    });

    test('gives up after maxAttempts', () async {
      var calls = 0;
      final provider = RemoteKeyProvider(
        maxAttempts: 2,
        retryDelay: Duration.zero,
        fetch: (_) async {
          calls++;
          throw StateError('down');
        },
      );

      await expectLater(
        provider.getKey(_context),
        throwsA(isA<KeyUnavailableException>()),
      );
      expect(calls, 2);
    });

    test('concurrent loads share a single fetch', () async {
      var calls = 0;
      final provider = RemoteKeyProvider(
        fetch: (_) async {
          calls++;
          await Future<void>.delayed(const Duration(milliseconds: 20));
          return _key();
        },
      );

      final keys = await Future.wait([
        provider.getKey(_context),
        provider.getKey(_context),
        provider.getKey(_context),
      ]);

      expect(calls, 1);
      for (final k in keys) {
        expect(k, equals(_key()));
      }
    });

    test('serves later loads from the cache', () async {
      var calls = 0;
      final provider = RemoteKeyProvider(
        cache: InMemoryKeyCache(),
        fetch: (_) async {
          calls++;
          return _key();
        },
      );

      await provider.getKey(_context);
      expect(await provider.getKey(_context), equals(_key()));
      expect(calls, 1);
    });

    test('hands out copies so a wiped key does not poison the cache',
        () async {
      final provider = RemoteKeyProvider(
        cache: InMemoryKeyCache(),
        fetch: (_) async => _key(),
      );

      final first = await provider.getKey(_context);
      LrtcCodec.wipe(first); // what the loader does after decrypting

      expect(await provider.getKey(_context), equals(_key()));
    });

    test('a wrong-length payload fails without poisoning the cache', () async {
      var calls = 0;
      final cache = InMemoryKeyCache();
      final provider = RemoteKeyProvider(
        cache: cache,
        retryDelay: Duration.zero,
        fetch: (_) async {
          calls++;
          // e.g. an error page served with HTTP 200
          return Uint8List.fromList(utf8.encode('<html>oops</html>'));
        },
      );

      await expectLater(
        provider.getKey(_context),
        throwsA(isA<KeyUnavailableException>()),
      );
      expect(calls, 1, reason: 'a non-key payload is a permanent failure');
      expect(await cache.read('3:yolo.tflite'), isNull,
          reason: 'the bad payload must never reach the cache');
    });

    test('a wrong-length cache entry is treated as a miss and re-fetched',
        () async {
      var calls = 0;
      final cache = InMemoryKeyCache();
      // Simulate a poisoned/tampered persistent store.
      await cache.write('3:yolo.tflite', Uint8List(16));

      final provider = RemoteKeyProvider(
        cache: cache,
        fetch: (_) async {
          calls++;
          return _key();
        },
      );

      expect(await provider.getKey(_context), equals(_key()));
      expect(calls, 1, reason: 'the invalid entry must not be served');
    });

    test('caches per keyId and label', () async {
      final requested = <String>[];
      final provider = RemoteKeyProvider(
        cache: InMemoryKeyCache(),
        fetch: (ctx) async {
          requested.add('${ctx.keyId}:${ctx.label}');
          return _key(ctx.keyId + 1);
        },
      );

      await provider.getKey(const KeyContext(keyId: 1, label: 'a'));
      await provider.getKey(const KeyContext(keyId: 2, label: 'b'));
      await provider.getKey(const KeyContext(keyId: 1, label: 'a'));

      expect(requested, ['1:a', '2:b']);
    });
  });

  group('decodeKeyBytes', () {
    test('accepts raw 32 bytes', () {
      expect(decodeKeyBytes(_key()), equals(_key()));
    });

    test('accepts a bare base64 string', () {
      expect(
        decodeKeyBytes(utf8.encode(base64Encode(_key()))),
        equals(_key()),
      );
    });

    test('accepts JSON with a base64 key field', () {
      final body = utf8.encode(jsonEncode({'key': base64Encode(_key())}));
      expect(decodeKeyBytes(body), equals(_key()));
    });

    test('rejects JSON without a key field', () {
      expect(
        () => decodeKeyBytes(utf8.encode('{"nope": 1}')),
        throwsA(isA<KeyUnavailableException>()),
      );
    });

    test('rejects malformed JSON', () {
      expect(
        () => decodeKeyBytes(utf8.encode('{"key": broken')),
        throwsA(isA<KeyUnavailableException>()),
      );
    });

    test('rejects malformed base64', () {
      expect(
        () => decodeKeyBytes(utf8.encode('not base64!!')),
        throwsA(isA<KeyUnavailableException>()),
      );
    });
  });

  group('InMemoryKeyCache', () {
    test('expires entries after the ttl', () async {
      var now = DateTime(2026);
      final cache = InMemoryKeyCache(
        ttl: const Duration(minutes: 10),
        clock: () => now,
      );

      await cache.write('k', _key());
      expect(await cache.read('k'), equals(_key()));

      now = now.add(const Duration(minutes: 11));
      expect(await cache.read('k'), isNull);
    });

    test('read returns copies', () async {
      final cache = InMemoryKeyCache();
      await cache.write('k', _key());

      LrtcCodec.wipe((await cache.read('k'))!);

      expect(await cache.read('k'), equals(_key()));
    });

    test('clear drops everything', () async {
      final cache = InMemoryKeyCache();
      await cache.write('k', _key());
      await cache.clear();
      expect(await cache.read('k'), isNull);
    });
  });
}
