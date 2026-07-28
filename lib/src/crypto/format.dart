import 'dart:typed_data';

import '../exceptions.dart';

/// The LRTC encrypted file format.
///
/// ```
/// [magic "LRTC" (4B)] [version (1B)] [keyId (2B, BE)] [IV (12B)] [ciphertext] [GCM tag (16B)]
/// ```
class LrtcEnvelope {
  const LrtcEnvelope({
    required this.version,
    required this.keyId,
    required this.iv,
    required this.cipherText,
    required this.tag,
  });

  static const List<int> magic = [0x4C, 0x52, 0x54, 0x43]; // "LRTC"
  static const int currentVersion = 1;
  static const int ivLength = 12;
  static const int tagLength = 16;
  static const int headerLength = 4 + 1 + 2 + ivLength;
  static const int minLength = headerLength + tagLength;

  final int version;

  /// Key identifier for key rotation, taken from the envelope header.
  final int keyId;

  final Uint8List iv;
  final Uint8List cipherText;
  final Uint8List tag;

  /// Parses [bytes]. Throws [InvalidFormatException] if they are not a valid
  /// LRTC envelope.
  factory LrtcEnvelope.parse(Uint8List bytes) {
    if (bytes.length < minLength) {
      throw const InvalidFormatException(
        'Input is too short to be an LRTC envelope. '
        'Did you pass a plaintext model? Encrypt it first with '
        '`dart run litert_crypto encrypt`.',
      );
    }
    for (var i = 0; i < magic.length; i++) {
      if (bytes[i] != magic[i]) {
        throw const InvalidFormatException(
          'Missing "LRTC" magic bytes. '
          'Did you pass a plaintext model? Encrypt it first with '
          '`dart run litert_crypto encrypt`.',
        );
      }
    }
    final version = bytes[4];
    if (version != currentVersion) {
      throw InvalidFormatException(
        'Unsupported format version $version (supported: $currentVersion).',
      );
    }
    final keyId = (bytes[5] << 8) | bytes[6];
    final iv = Uint8List.sublistView(bytes, 7, headerLength);
    final cipherText =
        Uint8List.sublistView(bytes, headerLength, bytes.length - tagLength);
    final tag = Uint8List.sublistView(bytes, bytes.length - tagLength);
    return LrtcEnvelope(
      version: version,
      keyId: keyId,
      iv: iv,
      cipherText: cipherText,
      tag: tag,
    );
  }

  /// Serializes this envelope back into the LRTC byte layout.
  Uint8List serialize() {
    final out = Uint8List(headerLength + cipherText.length + tagLength);
    out.setAll(0, magic);
    out[4] = version;
    out[5] = (keyId >> 8) & 0xFF;
    out[6] = keyId & 0xFF;
    out.setAll(7, iv);
    out.setAll(headerLength, cipherText);
    out.setAll(headerLength + cipherText.length, tag);
    return out;
  }
}
