import 'dart:convert';
import 'dart:typed_data';

import '../exceptions.dart';

/// The LRTC encrypted file format.
///
/// ```
/// [magic "LRTC" (4B)] [version (1B)] [keyId (2B, BE)] [labelLen (1B)]
/// [label (labelLen B, UTF-8)] [IV (16B)] [ciphertext] [HMAC-SHA256 tag (32B)]
/// ```
///
/// Encrypt-then-MAC: the tag covers the whole header as well as the
/// ciphertext, so tampering with the IV, keyId, or label is detected.
///
/// The [label] identifies the model and is mixed into key derivation, so two
/// models encrypted with the same master key end up with different working
/// keys — leaking one model's derived key does not unlock the others.
class LrtcEnvelope {
  const LrtcEnvelope({
    required this.version,
    required this.keyId,
    required this.label,
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

  /// magic + version + keyId + labelLen.
  static const int fixedHeaderLength = 4 + 1 + 2 + 1;

  /// Labels are length-prefixed with a single byte.
  static const int maxLabelLength = 255;

  final int version;

  /// Key identifier for key rotation, taken from the envelope header.
  final int keyId;

  /// Model identifier mixed into key derivation.
  final String label;

  /// The raw header bytes, authenticated by [tag].
  final Uint8List header;

  final Uint8List iv;
  final Uint8List cipherText;
  final Uint8List tag;

  /// Parses [bytes]. Throws [InvalidFormatException] if they are not a valid
  /// LRTC envelope.
  factory LrtcEnvelope.parse(Uint8List bytes) {
    const notAnEnvelope = InvalidFormatException(
      'Input is not a valid LRTC envelope. '
      'Did you pass a plaintext model? Encrypt it first with '
      '`dart run litert_crypto encrypt`.',
    );
    if (bytes.length < fixedHeaderLength) throw notAnEnvelope;
    for (var i = 0; i < magic.length; i++) {
      if (bytes[i] != magic[i]) throw notAnEnvelope;
    }
    final version = bytes[4];
    if (version != currentVersion) {
      throw InvalidFormatException(
        'Unsupported format version $version (supported: $currentVersion).',
      );
    }
    final labelLength = bytes[7];
    final headerLength = fixedHeaderLength + labelLength + ivLength;
    if (bytes.length < headerLength + tagLength) throw notAnEnvelope;

    final labelEnd = fixedHeaderLength + labelLength;
    return LrtcEnvelope(
      version: version,
      keyId: (bytes[5] << 8) | bytes[6],
      label: utf8.decode(
        Uint8List.sublistView(bytes, fixedHeaderLength, labelEnd),
        allowMalformed: true,
      ),
      header: Uint8List.sublistView(bytes, 0, headerLength),
      iv: Uint8List.sublistView(bytes, labelEnd, headerLength),
      cipherText:
          Uint8List.sublistView(bytes, headerLength, bytes.length - tagLength),
      tag: Uint8List.sublistView(bytes, bytes.length - tagLength),
    );
  }

  /// Builds the header bytes for the given values.
  static Uint8List buildHeader({
    required int version,
    required int keyId,
    required String label,
    required Uint8List iv,
  }) {
    final labelBytes = utf8.encode(label);
    if (labelBytes.length > maxLabelLength) {
      throw ArgumentError.value(
        label,
        'label',
        'must encode to at most $maxLabelLength UTF-8 bytes',
      );
    }
    final header =
        Uint8List(fixedHeaderLength + labelBytes.length + ivLength);
    header.setAll(0, magic);
    header[4] = version;
    header[5] = (keyId >> 8) & 0xFF;
    header[6] = keyId & 0xFF;
    header[7] = labelBytes.length;
    header.setAll(fixedHeaderLength, labelBytes);
    header.setAll(fixedHeaderLength + labelBytes.length, iv);
    return header;
  }

  /// Serializes this envelope back into the LRTC byte layout.
  Uint8List serialize() {
    final out = Uint8List(header.length + cipherText.length + tagLength);
    out.setAll(0, header);
    out.setAll(header.length, cipherText);
    out.setAll(header.length + cipherText.length, tag);
    return out;
  }
}
