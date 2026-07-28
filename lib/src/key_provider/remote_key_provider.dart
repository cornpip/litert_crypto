import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../exceptions.dart';
import 'key_cache.dart';
import 'key_provider.dart';

/// Builds request headers for a key fetch — the place to attach a session
/// token, a license identifier, or a freshly minted attestation token.
typedef KeyRequestHeaders = Future<Map<String, String>> Function(
  KeyContext context,
);

/// Turns a successful HTTP response into raw key bytes.
typedef KeyResponseDecoder = Uint8List Function(http.Response response);

/// Fetches the key from an HTTPS endpoint instead of shipping it in the app.
///
/// This moves the secret out of the binary, but it does **not** decide who
/// deserves a key: that gate is your server's job. On mobile, verifying a Play
/// Integrity / App Attest token before responding is what makes the difference;
/// on desktop there is no such attestation, so the gate has to be a credential
/// the user holds (license, account login). Without a gate, an attacker simply
/// asks your server for the key like any other client.
///
/// The provider adds the plumbing around that call: retries, timeouts,
/// single-flight de-duplication, and an optional [KeyCache] so a fetched key
/// survives repeated model loads (and, if you plug in secure storage, restarts).
///
/// ```dart
/// final provider = RemoteKeyProvider(
///   endpoint: Uri.parse('https://keys.example.com/model-key'),
///   headers: (ctx) async => {'Authorization': 'Bearer ${await session.token()}'},
///   cache: InMemoryKeyCache(ttl: const Duration(hours: 12)),
/// );
/// ```
class RemoteKeyProvider implements KeyProvider {
  RemoteKeyProvider({
    required this.endpoint,
    this.headers,
    this.cache,
    this.maxAttempts = 3,
    this.timeout = const Duration(seconds: 10),
    this.retryDelay = const Duration(milliseconds: 300),
    KeyResponseDecoder? decodeResponse,
    http.Client? client,
  })  : _decode = decodeResponse ?? decodeKeyResponse,
        _client = client ?? http.Client() {
    if (maxAttempts < 1) {
      throw ArgumentError.value(maxAttempts, 'maxAttempts', 'must be >= 1');
    }
  }

  /// Endpoint queried with `keyId` and `label` as query parameters.
  final Uri endpoint;

  /// Optional per-request headers (auth token, attestation token, ...).
  final KeyRequestHeaders? headers;

  /// Optional store so repeated loads do not re-fetch. Null disables caching.
  final KeyCache? cache;

  /// Attempts per fetch, including the first one.
  final int maxAttempts;

  /// Per-attempt timeout.
  final Duration timeout;

  /// Delay between attempts.
  final Duration retryDelay;

  final KeyResponseDecoder _decode;
  final http.Client _client;
  final Map<String, Future<Uint8List>> _inFlight = {};

  @override
  Future<Uint8List> getKey(KeyContext context) async {
    final cacheKey = '${context.keyId}:${context.label}';

    final cached = await cache?.read(cacheKey);
    if (cached != null) return cached;

    // Concurrent model loads share one request instead of stampeding.
    final pending = _inFlight[cacheKey] ??= _fetch(context).whenComplete(() {
      _inFlight.remove(cacheKey);
    });
    final key = await pending;

    // Fresh copy per caller: the loader zeroes what it receives.
    return Uint8List.fromList(key);
  }

  /// Releases the underlying HTTP client.
  void close() => _client.close();

  Future<Uint8List> _fetch(KeyContext context) async {
    final uri = endpoint.replace(
      queryParameters: {
        ...endpoint.queryParameters,
        'keyId': '${context.keyId}',
        if (context.label.isNotEmpty) 'label': context.label,
      },
    );

    Object? lastError;
    for (var attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        final response = await _client
            .get(uri, headers: await headers?.call(context))
            .timeout(timeout);

        if (response.statusCode == 200) {
          final key = _decode(response);
          await cache?.write('${context.keyId}:${context.label}', key);
          return key;
        }
        // Client-side rejections are final: retrying will not fix auth.
        if (response.statusCode < 500) {
          throw KeyUnavailableException(
            'Key endpoint refused the request (HTTP ${response.statusCode}).',
          );
        }
        lastError = 'HTTP ${response.statusCode}';
      } on KeyUnavailableException {
        rethrow;
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

/// Default response decoder.
///
/// Accepts either a JSON body with a base64 `key` field, a bare base64 string,
/// or the raw key bytes.
Uint8List decodeKeyResponse(http.Response response) {
  final bytes = response.bodyBytes;
  final text = response.body.trim();

  if (text.startsWith('{')) {
    final decoded = jsonDecode(text);
    final value = decoded is Map ? decoded['key'] : null;
    if (value is! String) {
      throw const KeyUnavailableException(
        'Key endpoint returned JSON without a base64 "key" field.',
      );
    }
    return _base64(value);
  }
  if (bytes.length == 32) return Uint8List.fromList(bytes);
  return _base64(text);
}

Uint8List _base64(String value) {
  try {
    return Uint8List.fromList(base64Decode(value));
  } on FormatException catch (e) {
    throw KeyUnavailableException('Key endpoint returned malformed base64: $e');
  }
}
