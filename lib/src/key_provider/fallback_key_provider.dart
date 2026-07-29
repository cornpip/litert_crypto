import 'dart:typed_data';

import '../exceptions.dart';
import 'key_provider.dart';

/// Tries multiple providers in order and returns the first successful key.
///
/// Example: local cache first, then a remote server.
/// ```dart
/// FallbackKeyProvider([cachedProvider, remoteProvider])
/// ```
///
/// Any [Exception] from a provider moves on to the next one — a transient
/// I/O failure in an early provider must not block a later one that would
/// succeed. [Error]s (programming bugs) still propagate.
class FallbackKeyProvider implements KeyProvider {
  const FallbackKeyProvider(this._providers);

  final List<KeyProvider> _providers;

  @override
  Future<Uint8List> getKey(KeyContext context) async {
    if (_providers.isEmpty) {
      throw const KeyUnavailableException('No key providers configured.');
    }
    final failures = <String>[];
    for (final provider in _providers) {
      try {
        return await provider.getKey(context);
      } on KeyUnavailableException catch (e) {
        failures.add('${provider.runtimeType}: ${e.message}');
      } on Exception catch (e) {
        failures.add('${provider.runtimeType}: $e');
      }
    }
    throw KeyUnavailableException(
      'All key providers failed — ${failures.join(' / ')}',
    );
  }
}
