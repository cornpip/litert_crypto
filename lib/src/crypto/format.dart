import 'dart:convert';
import 'dart:typed_data';

import '../exceptions.dart';

/// The LRTC encrypted file format, version 2.
///
/// ```
/// [magic "LRTC" (4B)] [version (1B)] [keyId (2B, BE)] [labelLen (1B)]
/// [label (labelLen B, UTF-8)] [IV (12B)] [ciphertext ‖ GCM tag (16B)]
/// ```
///
/// AES-256-GCM with the whole header as additional authenticated data, so
/// tampering with the IV, keyId, or label is detected by the tag at the end
/// of the sealed payload.
///
/// The [label] identifies the model and is mixed into key derivation, so two
/// models encrypted with the same master key end up with different working
/// keys — leaking one model's derived key does not unlock the others.
///
/// Version 1 (AES-CTR + HMAC-SHA256, written by litert_crypto 0.1.0) is not
/// readable; parsing reports it with a re-encrypt hint. The format changed
/// when decryption moved to BoringSSL, whose one-shot AEAD is the fast path.
class LrtcEnvelope {
  const LrtcEnvelope({
    required this.version,
    required this.keyId,
    required this.label,
    required this.header,
    required this.iv,
    required this.sealed,
  });

  static const List<int> magic = [0x4C, 0x52, 0x54, 0x43]; // "LRTC"
  static const int currentVersion = 2;

  /// AES-GCM nonce length (the 96-bit fast path every implementation takes).
  static const int ivLength = 12;

  /// AES-GCM tag length, appended to the ciphertext inside [sealed].
  static const int tagLength = 16;

  /// magic + version + keyId + labelLen.
  static const int fixedHeaderLength = 4 + 1 + 2 + 1;

  /// Labels are length-prefixed with a single byte.
  static const int maxLabelLength = 255;

  final int version;

  /// Key identifier for key rotation, taken from the envelope header.
  final int keyId;

  /// Model identifier mixed into key derivation.
  final String label;

  /// The raw header bytes, authenticated as the AEAD's additional data.
  final Uint8List header;

  final Uint8List iv;

  /// Ciphertext with the 16-byte GCM tag appended — the AEAD's input shape.
  final Uint8List sealed;

  /// Model size in bytes once decrypted.
  int get plainLength => sealed.length - tagLength;

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
      if (bytes[i] != magic[i]) {
        // A wrong magic is usually a mistake worth diagnosing precisely: a
        // plaintext .tflite reaching the loader means the asset was bundled
        // without encryption — the security failure already happened at
        // build time, so name it instead of a generic format error.
        if (_looksLikeTflite(bytes)) {
          throw const InvalidFormatException(
            'This is a plaintext TensorFlow Lite model (TFL3), not an LRTC '
            'file — it was never encrypted. If it came from your app '
            "bundle, the asset's pubspec entry is missing the litert_crypto "
            'transformer; any release built this way ships the model in '
            'the clear.',
          );
        }
        throw notAnEnvelope;
      }
    }
    final version = bytes[4];
    if (version != currentVersion) {
      throw InvalidFormatException(
        version == 1
            ? 'This is a version 1 file, written by litert_crypto 0.1.0. The '
                'format changed in 0.2.0 — re-encrypt the model with the '
                'current CLI: `dart run litert_crypto encrypt`.'
            : 'Unsupported format version $version '
                '(supported: $currentVersion).',
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
      sealed: Uint8List.sublistView(bytes, headerLength),
    );
  }

  /// TFLite flatbuffers carry the file identifier "TFL3" at bytes 4–7
  /// (after the 4-byte root offset).
  static bool _looksLikeTflite(Uint8List bytes) {
    const tfl3 = [0x54, 0x46, 0x4C, 0x33]; // "TFL3"
    if (bytes.length < 8) return false;
    for (var i = 0; i < tfl3.length; i++) {
      if (bytes[4 + i] != tfl3[i]) return false;
    }
    return true;
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
    final out = Uint8List(header.length + sealed.length);
    out.setAll(0, header);
    out.setAll(header.length, sealed);
    return out;
  }
}
