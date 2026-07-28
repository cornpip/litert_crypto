import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:litert_crypto/codec.dart';
import 'package:litert_crypto/src/key_provider/key_cache.dart';
import 'package:litert_crypto/src/key_provider/key_provider.dart';
import 'package:litert_crypto/src/key_provider/remote_key_provider.dart';

Uint8List _key([int seed = 7]) =>
    Uint8List.fromList(List.generate(32, (i) => (i * seed + 3) & 0xFF));

const _context = KeyContext(keyId: 3, label: 'yolo.tflite');

void main() {
  group('RemoteKeyProvider', () {
    test('fetches a key and passes keyId/label to the endpoint', () async {
      late Uri seen;
      final provider = RemoteKeyProvider(
        endpoint: Uri.parse('https://keys.test/model-key'),
        client: MockClient((request) async {
          seen = request.url;
          return http.Response(
            jsonEncode({'key': base64Encode(_key())}),
            200,
            headers: {'content-type': 'application/json'},
          );
        }),
      );

      expect(await provider.getKey(_context), equals(_key()));
      expect(seen.queryParameters['keyId'], '3');
      expect(seen.queryParameters['label'], 'yolo.tflite');
    });

    test('sends headers built per request (auth/attestation token)', () async {
      Map<String, String>? seen;
      final provider = RemoteKeyProvider(
        endpoint: Uri.parse('https://keys.test/k'),
        headers: (ctx) async => {'Authorization': 'Bearer ${ctx.label}'},
        client: MockClient((request) async {
          seen = request.headers;
          return http.Response(base64Encode(_key()), 200);
        }),
      );

      await provider.getKey(_context);
      expect(seen?['Authorization'], 'Bearer yolo.tflite');
    });

    test('accepts a raw 32-byte body as well as base64', () async {
      final provider = RemoteKeyProvider(
        endpoint: Uri.parse('https://keys.test/k'),
        client: MockClient((_) async => http.Response.bytes(_key(), 200)),
      );

      expect(await provider.getKey(_context), equals(_key()));
    });

    test('retries server errors, then succeeds', () async {
      var calls = 0;
      final provider = RemoteKeyProvider(
        endpoint: Uri.parse('https://keys.test/k'),
        retryDelay: Duration.zero,
        client: MockClient((_) async {
          calls++;
          if (calls < 3) return http.Response('boom', 503);
          return http.Response(base64Encode(_key()), 200);
        }),
      );

      expect(await provider.getKey(_context), equals(_key()));
      expect(calls, 3);
    });

    test('does not retry an auth rejection', () async {
      var calls = 0;
      final provider = RemoteKeyProvider(
        endpoint: Uri.parse('https://keys.test/k'),
        retryDelay: Duration.zero,
        client: MockClient((_) async {
          calls++;
          return http.Response('nope', 403);
        }),
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
        endpoint: Uri.parse('https://keys.test/k'),
        maxAttempts: 2,
        retryDelay: Duration.zero,
        client: MockClient((_) async {
          calls++;
          return http.Response('down', 500);
        }),
      );

      await expectLater(
        provider.getKey(_context),
        throwsA(isA<KeyUnavailableException>()),
      );
      expect(calls, 2);
    });

    test('concurrent loads share a single request', () async {
      var calls = 0;
      final provider = RemoteKeyProvider(
        endpoint: Uri.parse('https://keys.test/k'),
        client: MockClient((_) async {
          calls++;
          await Future<void>.delayed(const Duration(milliseconds: 20));
          return http.Response(base64Encode(_key()), 200);
        }),
      );

      final keys = await Future.wait([
        provider.getKey(_context),
        provider.getKey(_context),
        provider.getKey(_context),
      ]);

      expect(calls, 1);
      expect(keys.every((k) => k.every((b) => b == 0)), isFalse);
      for (final k in keys) {
        expect(k, equals(_key()));
      }
    });

    test('serves later loads from the cache', () async {
      var calls = 0;
      final provider = RemoteKeyProvider(
        endpoint: Uri.parse('https://keys.test/k'),
        cache: InMemoryKeyCache(),
        client: MockClient((_) async {
          calls++;
          return http.Response(base64Encode(_key()), 200);
        }),
      );

      await provider.getKey(_context);
      expect(await provider.getKey(_context), equals(_key()));
      expect(calls, 1);
    });

    test('hands out copies so a wiped key does not poison the cache',
        () async {
      final provider = RemoteKeyProvider(
        endpoint: Uri.parse('https://keys.test/k'),
        cache: InMemoryKeyCache(),
        client: MockClient((_) async => http.Response(base64Encode(_key()), 200)),
      );

      final first = await provider.getKey(_context);
      LrtcCodec.wipe(first); // what the loader does after decrypting

      expect(await provider.getKey(_context), equals(_key()));
    });

    test('malformed payloads surface as KeyUnavailableException', () async {
      final provider = RemoteKeyProvider(
        endpoint: Uri.parse('https://keys.test/k'),
        client: MockClient((_) async => http.Response('{"nope": 1}', 200)),
      );

      await expectLater(
        provider.getKey(_context),
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
