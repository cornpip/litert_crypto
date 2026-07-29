import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../crypto/codec.dart';
import '../exceptions.dart';
import 'key_cache.dart';
import 'key_provider.dart';

/// Retrieves raw key bytes for [context] from wherever you keep them.
///
/// Throw [KeyUnavailableException] for permanent failures (rejected auth,
/// unknown key id) — those are not retried. Any other error is treated as
/// transient and retried.
typedef KeyFetcher = Future<Uint8List> Function(KeyContext context);

/// Fetches the key from outside the app — typically an HTTPS endpoint — instead
/// of shipping it inside the binary.
///
/// The transport is yours: pass a [fetch] callback built on `package:http`,
/// dio, a platform channel, or anything else. This provider supplies the
/// plumbing around it that is easy to get wrong:
///
/// * retries with a delay, skipping permanent failures
/// * single-flight de-duplication, so concurrent model loads issue one fetch
/// * an optional [KeyCache], with copy semantics that survive the loader
///   zeroing the key it was handed
///
/// ```dart
/// final provider = RemoteKeyProvider(
///   fetch: (ctx) async {
///     final res = await http.get(
///       Uri.parse('https://keys.example.com/model-key?keyId=${ctx.keyId}'),
///       headers: {'Authorization': 'Bearer ${await session.token()}'},
///     );
///     if (res.statusCode == 403) {
///       throw const KeyUnavailableException('not entitled'); // no retry
///     }
///     if (res.statusCode != 200) throw StateError('HTTP ${res.statusCode}');
///     return decodeKeyBytes(res.bodyBytes);
///   },
///   cache: InMemoryKeyCache(ttl: const Duration(hours: 12)),
/// );
/// ```
///
/// Fetching remotely moves the secret out of your binary, but it does **not**
/// decide who deserves a key: that gate is your server's job. On mobile,
/// verifying a Play Integrity / App Attest token before responding is what gives
/// this teeth; on desktop there is no such attestation, so the gate has to be a
/// credential the user holds (license, account login). Without a gate, an
/// attacker simply asks your server for the key like any other client.
class RemoteKeyProvider implements KeyProvider {
  RemoteKeyProvider({
    required this.fetch,
    this.cache,
    this.maxAttempts = 3,
    this.retryDelay = const Duration(milliseconds: 300),
  }) {
    if (maxAttempts < 1) {
      throw ArgumentError.value(maxAttempts, 'maxAttempts', 'must be >= 1');
    }
  }

  /// How key bytes are obtained.
  final KeyFetcher fetch;

  /// Optional store so repeated loads do not re-fetch. Null disables caching.
  final KeyCache? cache;

  /// Attempts per fetch, including the first one.
  final int maxAttempts;

  /// Delay between attempts.
  final Duration retryDelay;

  final Map<String, Future<Uint8List>> _inFlight = {};

  @override
  Future<Uint8List> getKey(KeyContext context) async {
    final cacheKey = '${context.keyId}:${context.label}';

    // A wrong-length entry (an older poisoned cache, or a tampered persistent
    // store) is treated as a miss, so a re-fetch can heal it.
    final cached = await cache?.read(cacheKey);
    if (cached != null && cached.length == LrtcCodec.keyLength) return cached;

    final pending = _inFlight[cacheKey] ??=
        _fetchWithRetry(context, cacheKey).whenComplete(() {
      _inFlight.remove(cacheKey);
    });
    final key = await pending;

    // Fresh copy per caller: the loader zeroes what it receives.
    return Uint8List.fromList(key);
  }

  Future<Uint8List> _fetchWithRetry(KeyContext context, String cacheKey) async {
    Object? lastError;
    for (var attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        final key = await fetch(context);
        // Validate before the key can reach the cache: a bad payload written
        // there would poison every later load until the entry expires.
        if (key.length != LrtcCodec.keyLength) {
          throw KeyUnavailableException(
            'Fetcher returned ${key.length} bytes for $cacheKey; expected '
            '${LrtcCodec.keyLength}. The response is probably not a key.',
          );
        }
        await cache?.write(cacheKey, key);
        return key;
      } on KeyUnavailableException {
        rethrow; // permanent: retrying will not help
      } catch (e) {
        lastError = e;
      }
      if (attempt < maxAttempts) await Future<void>.delayed(retryDelay);
    }
    throw KeyUnavailableException(
      'Key fetch failed after $maxAttempts attempt(s): $lastError',
    );
  }
}

/// Interprets a key payload: JSON with a base64 `key` field, a bare base64
/// string, or the raw 32 key bytes.
///
/// A convenience for [KeyFetcher] implementations; use your own parsing when
/// your service speaks a different shape.
Uint8List decodeKeyBytes(List<int> body) {
  if (body.length == 32) return Uint8List.fromList(body);

  final String text;
  try {
    text = utf8.decode(body).trim();
  } on FormatException {
    throw const KeyUnavailableException(
      'Key payload is neither 32 raw bytes nor text.',
    );
  }

  if (text.startsWith('{')) {
    final Object? decoded;
    try {
      decoded = jsonDecode(text);
    } on FormatException catch (e) {
      throw KeyUnavailableException(
        'Key payload looks like JSON but does not parse: $e',
      );
    }
    final value = decoded is Map ? decoded['key'] : null;
    if (value is! String) {
      throw const KeyUnavailableException(
        'Key payload is JSON without a base64 "key" field.',
      );
    }
    return _base64(value);
  }
  return _base64(text);
}

Uint8List _base64(String value) {
  try {
    return Uint8List.fromList(base64Decode(value));
  } on FormatException catch (e) {
    throw KeyUnavailableException('Key payload has malformed base64: $e');
  }
}
