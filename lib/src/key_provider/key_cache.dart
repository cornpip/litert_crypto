import 'dart:typed_data';

/// Storage for keys fetched from a remote service.
///
/// Implementations decide *where* a key rests between runs — an encrypted
/// preference store, the platform keychain, or nothing at all. The package
/// deliberately ships no plugin-backed implementation so that it stays pure
/// Dart; wrap `flutter_secure_storage` (or your own channel) to persist keys.
///
/// **Return a fresh copy from [read].** Keys handed to the loader are zeroed
/// after use, so a cache that returns its own buffer would erase itself.
abstract interface class KeyCache {
  /// Returns the cached key for [cacheKey], or null when absent/expired.
  Future<Uint8List?> read(String cacheKey);

  /// Stores [key] under [cacheKey].
  Future<void> write(String cacheKey, Uint8List key);

  /// Drops every cached key (e.g. after a rotation or sign-out).
  Future<void> clear();
}

/// Process-lifetime cache with an optional expiry.
///
/// Keeps a fetched key out of repeated network round trips without ever
/// touching disk. Everything is lost when the process exits — which is the
/// safe default.
class InMemoryKeyCache implements KeyCache {
  InMemoryKeyCache({this.ttl, DateTime Function()? clock})
      : _clock = clock ?? DateTime.now;

  /// How long an entry stays valid. Null means "until the process exits".
  final Duration? ttl;

  final DateTime Function() _clock;
  final Map<String, _Entry> _entries = {};

  @override
  Future<Uint8List?> read(String cacheKey) async {
    final entry = _entries[cacheKey];
    if (entry == null) return null;
    if (entry.expiresAt != null && !_clock().isBefore(entry.expiresAt!)) {
      _entries.remove(cacheKey);
      return null;
    }
    return Uint8List.fromList(entry.key);
  }

  @override
  Future<void> write(String cacheKey, Uint8List key) async {
    _entries[cacheKey] = _Entry(
      Uint8List.fromList(key),
      ttl == null ? null : _clock().add(ttl!),
    );
  }

  @override
  Future<void> clear() async => _entries.clear();
}

class _Entry {
  _Entry(this.key, this.expiresAt);

  final Uint8List key;
  final DateTime? expiresAt;
}
