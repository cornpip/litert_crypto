import 'dart:typed_data';

/// Context passed to a [KeyProvider] when a key is requested.
class KeyContext {
  const KeyContext({required this.keyId, this.source, this.label = ''});

  /// Key identifier recorded in the encrypted file header (for key rotation).
  final int keyId;

  /// Where the model came from (asset path, file path, ...). For logging and
  /// per-model branching.
  final String? source;

  /// Model label recorded in the envelope. Mixed into key derivation by the
  /// codec; also useful for picking a key per model.
  final String label;

  @override
  String toString() =>
      'KeyContext(keyId: $keyId, label: "$label", source: $source)';
}

/// Abstraction over where the decryption key comes from.
///
/// This package does not decide your key management *policy* — where a key
/// lives and how it is protected is determined by your app's distribution
/// model, and the responsibility stays with you. This interface is only the
/// point where that policy plugs in.
abstract interface class KeyProvider {
  /// Returns a 32-byte AES-256 key.
  ///
  /// **Return a fresh copy every time.** The returned bytes are zeroed once
  /// the working subkeys have been derived, so a provider that hands out its
  /// own retained buffer would destroy its key on first use.
  ///
  /// Implementations should throw `KeyUnavailableException` when the key
  /// cannot be provided.
  Future<Uint8List> getKey(KeyContext context);
}
