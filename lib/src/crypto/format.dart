import 'dart:typed_data';

import '../exceptions.dart';

/// The LRTC encrypted file format.
///
/// ```
/// [magic "LRTC" (4B)] [version (1B)] [keyId (2B, BE)] [IV (16B)] [ciphertext] [HMAC-SHA256 tag (32B)]
/// ```
///
/// Encrypt-then-MAC: the tag covers the header *and* the ciphertext, so header
/// tampering (IV, keyId) is detected too.
class LrtcEnvelope {
  const LrtcEnvelope({
    required this.version,
    required this.keyId,
    required this.header,
    required this.iv,
    required this.cipherText,
    required this.tag,
  });

  static const List<int> magic = [0x4C, 0x52, 0x54, 0x43]; // "LRTC"
  static const int currentVersion = 1;

  /// AES-CTR nonce length (one AES block).
  static const int ivLength = 16;

  /// HMAC-SHA256 output length.
  static const int tagLength = 32;

  static const int headerLength = 4 + 1 + 2 + ivLength;
  static const int minLength = headerLength + tagLength;

  final int version;

  /// Key identifier for key rotation, taken from the envelope header.
  final int keyId;

  /// The raw header bytes, authenticated by [tag].
  final Uint8List header;

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
    return LrtcEnvelope(
      version: version,
      keyId: (bytes[5] << 8) | bytes[6],
      header: Uint8List.sublistView(bytes, 0, headerLength),
      iv: Uint8List.sublistView(bytes, 7, headerLength),
      cipherText:
          Uint8List.sublistView(bytes, headerLength, bytes.length - tagLength),
      tag: Uint8List.sublistView(bytes, bytes.length - tagLength),
    );
  }

  /// Builds the header bytes for the given [version], [keyId] and [iv].
  static Uint8List buildHeader({
    required int version,
    required int keyId,
    required Uint8List iv,
  }) {
    final header = Uint8List(headerLength);
    header.setAll(0, magic);
    header[4] = version;
    header[5] = (keyId >> 8) & 0xFF;
    header[6] = keyId & 0xFF;
    header.setAll(7, iv);
    return header;
  }

  /// Serializes this envelope back into the LRTC byte layout.
  Uint8List serialize() {
    final out = Uint8List(headerLength + cipherText.length + tagLength);
    out.setAll(0, header);
    out.setAll(headerLength, cipherText);
    out.setAll(headerLength + cipherText.length, tag);
    return out;
  }
}
