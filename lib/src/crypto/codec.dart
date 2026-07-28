import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart' show constantTimeBytesEquality;

import '../exceptions.dart';
import 'format.dart';

/// Encrypts/decrypts the LRTC format: AES-256-CTR with encrypt-then-MAC
/// (HMAC-SHA256).
///
/// AES-GCM was measured ~3.5x slower on a 10 MB model in pure Dart (GHASH has
/// no hardware acceleration here), which matters because model decryption sits
/// on the app's load path. CTR + HMAC keeps authenticated encryption at a much
/// lower cost.
///
/// Encryption and MAC keys are derived from the caller's 32-byte key with
/// HKDF-SHA256, so the same key material is never used for both purposes.
///
/// Pure Dart with no Flutter dependency — shared by the CLI (`bin/`) and the
/// runtime loader.
class LrtcCodec {
  LrtcCodec._();

  /// Required length of the master key supplied by a `KeyProvider`.
  static const int keyLength = 32;

  static const List<int> _encInfo = [
    0x65, 0x6E, 0x63, 0x3A, 0x76, 0x31, // "enc:v1"
  ];
  static const List<int> _macInfo = [
    0x6D, 0x61, 0x63, 0x3A, 0x76, 0x31, // "mac:v1"
  ];

  static final AesCtr _cipher =
      AesCtr.with256bits(macAlgorithm: MacAlgorithm.empty);
  static final Hmac _hmac = Hmac.sha256();
  static final Hkdf _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: keyLength);

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
    final (encKey, macKey) = await _deriveKeys(key);
    final iv = Uint8List.fromList(_cipher.newNonce());
    final header = LrtcEnvelope.buildHeader(
      version: LrtcEnvelope.currentVersion,
      keyId: keyId,
      iv: iv,
    );

    final box = await _cipher.encrypt(plain, secretKey: encKey, nonce: iv);
    final cipherText = Uint8List.fromList(box.cipherText);
    final tag = await _tag(header, cipherText, macKey);

    return LrtcEnvelope(
      version: LrtcEnvelope.currentVersion,
      keyId: keyId,
      header: header,
      iv: iv,
      cipherText: cipherText,
      tag: tag,
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
    final (encKey, macKey) = await _deriveKeys(key);

    // Verify before decrypting: a wrong key or tampered bytes never reach
    // the AES step.
    final expected = await _tag(envelope.header, envelope.cipherText, macKey);
    if (!constantTimeBytesEquality.equals(expected, envelope.tag)) {
      throw const DecryptionFailedException(
        'MAC verification failed — wrong key or tampered data.',
      );
    }

    final clear = await _cipher.decrypt(
      SecretBox(envelope.cipherText, nonce: envelope.iv, mac: Mac.empty),
      secretKey: encKey,
    );
    return clear is Uint8List ? clear : Uint8List.fromList(clear);
  }

  static Future<(SecretKey, SecretKey)> _deriveKeys(Uint8List key) async {
    final master = SecretKey(key);
    final encKey = await _hkdf.deriveKey(secretKey: master, info: _encInfo);
    final macKey = await _hkdf.deriveKey(secretKey: master, info: _macInfo);
    return (encKey, macKey);
  }

  static Future<Uint8List> _tag(
    Uint8List header,
    Uint8List cipherText,
    SecretKey macKey,
  ) async {
    final signed = Uint8List(header.length + cipherText.length)
      ..setAll(0, header)
      ..setAll(header.length, cipherText);
    final mac = await _hmac.calculateMac(signed, secretKey: macKey);
    return Uint8List.fromList(mac.bytes);
  }

  static void _checkKey(Uint8List key) {
    if (key.length != keyLength) {
      throw KeyUnavailableException(
        'Expected a $keyLength-byte key, got ${key.length} bytes.',
      );
    }
  }
}
