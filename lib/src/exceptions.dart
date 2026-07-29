/// Common exceptions for litert_crypto.
///
/// Design principle "fail loudly": wrong keys, integrity failures, and format
/// errors are never silently ignored — they always surface as one of the
/// types below.
sealed class LitertCryptoException implements Exception {
  const LitertCryptoException(this.message);

  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

/// The input bytes are not in the LRTC format, or the envelope is corrupted.
final class InvalidFormatException extends LitertCryptoException {
  const InvalidFormatException(super.message);
}

/// The [KeyProvider] could not supply a key.
final class KeyUnavailableException extends LitertCryptoException {
  const KeyUnavailableException(super.message);
}

/// Decryption failed — wrong key or tampered ciphertext (HMAC verification
/// failed).
final class DecryptionFailedException extends LitertCryptoException {
  const DecryptionFailedException(super.message);
}
