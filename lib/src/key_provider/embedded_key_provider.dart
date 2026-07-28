import 'dart:typed_data';

import '../exceptions.dart';
import 'key_provider.dart';

/// Returns a key embedded in the app.
///
/// **Protection strength: low.** The key ships inside your binary and can be
/// recovered through reverse engineering. This is the minimum defense — it
/// only stops "unzip the bundle and grab the model". If you need more, use a
/// provider whose key lives outside the binary (license file, secure storage,
/// server).
///
/// [EmbeddedKeyProvider.fromParts] is a helper that XOR-combines key parts at
/// runtime so the finished key never appears as a literal in the binary —
/// this raises the effort required, it does not hide the key.
class EmbeddedKeyProvider implements KeyProvider {
  EmbeddedKeyProvider(Uint8List key) : _key = Uint8List.fromList(key);

  /// Builds the key by XOR-combining equally sized [parts].
  ///
  /// Example: keep two random 32-byte parts A and B in different places in
  /// your code and call `fromParts([A, B])` — the actual key (A ^ B) exists
  /// nowhere in the binary as a literal.
  factory EmbeddedKeyProvider.fromParts(List<Uint8List> parts) {
    if (parts.isEmpty) {
      throw const KeyUnavailableException(
        'fromParts requires at least one part.',
      );
    }
    final length = parts.first.length;
    final key = Uint8List(length);
    for (final part in parts) {
      if (part.length != length) {
        throw const KeyUnavailableException(
          'All key parts must have the same length.',
        );
      }
      for (var i = 0; i < length; i++) {
        key[i] ^= part[i];
      }
    }
    return EmbeddedKeyProvider(key);
  }

  final Uint8List _key;

  // A fresh copy per call: the codec zeroes the key it receives.
  @override
  Future<Uint8List> getKey(KeyContext context) async =>
      Uint8List.fromList(_key);
}
