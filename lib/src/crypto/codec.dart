import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../exceptions.dart';
import 'format.dart';

/// Encrypts/decrypts the LRTC format (AES-256-GCM).
///
/// Pure Dart with no Flutter dependency — shared by the CLI (`bin/`) and the
/// runtime loader.
class LrtcCodec {
  LrtcCodec._();

  static const int keyLength = 32;

  static final AesGcm _algorithm = AesGcm.with256bits();

  /// Encrypts [plain] and returns LRTC-formatted bytes.
  static Future<Uint8List> encrypt(
    Uint8List plain,
    Uint8List key, {
    int keyId = 0,
  }) async {
    _checkKey(key);
    if (keyId < 0 || keyId > 0xFFFF) {
      throw ArgumentError.value(keyId, 'keyId', 'must fit in uint16');
    }
    final box = await _algorithm.encrypt(
      plain,
      secretKey: SecretKey(key),
      nonce: _algorithm.newNonce(),
    );
    return LrtcEnvelope(
      version: LrtcEnvelope.currentVersion,
      keyId: keyId,
      iv: Uint8List.fromList(box.nonce),
      cipherText: Uint8List.fromList(box.cipherText),
      tag: Uint8List.fromList(box.mac.bytes),
    ).serialize();
  }

  /// Decrypts LRTC-formatted [bytes] and returns the plaintext.
  ///
  /// Throws [DecryptionFailedException] on a wrong key or tampered data.
  static Future<Uint8List> decrypt(Uint8List bytes, Uint8List key) {
    return decryptEnvelope(LrtcEnvelope.parse(bytes), key);
  }

  /// Decrypts an already-parsed [envelope].
  static Future<Uint8List> decryptEnvelope(
    LrtcEnvelope envelope,
    Uint8List key,
  ) async {
    _checkKey(key);
    try {
      final clear = await _algorithm.decrypt(
        SecretBox(
          envelope.cipherText,
          nonce: envelope.iv,
          mac: Mac(envelope.tag),
        ),
        secretKey: SecretKey(key),
      );
      return clear is Uint8List ? clear : Uint8List.fromList(clear);
    } on SecretBoxAuthenticationError {
      throw const DecryptionFailedException(
        'GCM authentication failed — wrong key or tampered data.',
      );
    }
  }

  static void _checkKey(Uint8List key) {
    if (key.length != keyLength) {
      throw KeyUnavailableException(
        'Expected a $keyLength-byte AES-256 key, got ${key.length} bytes.',
      );
    }
  }
}
