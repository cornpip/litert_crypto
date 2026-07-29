import 'dart:convert';
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
/// HKDF-SHA256, mixing in the envelope's label so that each model gets its own
/// working keys. Derived subkeys are destroyed as soon as they are used; the
/// caller's key buffer is left untouched (see [wipe] to clear it yourself).
///
/// Pure Dart with no Flutter dependency — shared by the CLI (`bin/`) and the
/// runtime loader.
class LrtcCodec {
  LrtcCodec._();

  /// Required length of the master key supplied by a `KeyProvider`.
  static const int keyLength = 32;

  static final AesCtr _cipher =
      AesCtr.with256bits(macAlgorithm: MacAlgorithm.empty);
  static final Hmac _hmac = Hmac.sha256();
  static final Hkdf _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: keyLength);

  /// Encrypts [plain] and returns LRTC-formatted bytes.
  ///
  /// [label] identifies the model and is bound into both the envelope and key
  /// derivation; the same label must be present when decrypting (it travels
  /// inside the envelope, so callers do not need to track it).
  static Future<Uint8List> encrypt(
    Uint8List plain,
    Uint8List key, {
    int keyId = 0,
    String label = '',
  }) async {
    _checkKey(key);
    if (keyId < 0 || keyId > 0xFFFF) {
      throw ArgumentError.value(keyId, 'keyId', 'must fit in uint16');
    }
    final iv = Uint8List.fromList(_cipher.newNonce());
    final header = LrtcEnvelope.buildHeader(
      version: LrtcEnvelope.currentVersion,
      keyId: keyId,
      label: label,
      iv: iv,
    );

    final (encKey, macKey) = await _deriveKeys(key, label);
    try {
      final box = await _cipher.encrypt(plain, secretKey: encKey, nonce: iv);
      final cipherText = Uint8List.fromList(box.cipherText);
      final tag = await _tag(header, cipherText, macKey);

      return LrtcEnvelope(
        version: LrtcEnvelope.currentVersion,
        keyId: keyId,
        label: label,
        header: header,
        iv: iv,
        cipherText: cipherText,
        tag: tag,
      ).serialize();
    } finally {
      encKey.destroy();
      macKey.destroy();
    }
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
    final (encKey, macKey) = await _deriveKeys(key, envelope.label);
    try {
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
      if (clear is Uint8List) return clear;
      // Copying leaves the cipher's own list behind; zero it so only the
      // returned buffer holds the plaintext.
      final copied = Uint8List.fromList(clear);
      clear.fillRange(0, clear.length, 0);
      return copied;
    } finally {
      encKey.destroy();
      macKey.destroy();
    }
  }

  /// Overwrites [bytes] with zeros.
  ///
  /// Used on plaintext and key material once it is no longer needed, so it does
  /// not linger in the heap until garbage collection.
  static void wipe(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);

  /// Derives independent encryption and MAC keys for [label].
  ///
  /// The caller's [key] is not modified — clearing it is the caller's call
  /// (the loader does exactly that once a model is decrypted).
  static Future<(SecretKeyData, SecretKeyData)> _deriveKeys(
    Uint8List key,
    String label,
  ) async {
    final master = SecretKey(Uint8List.fromList(key));
    try {
      final encKey = await _hkdf.deriveKey(
        secretKey: master,
        info: utf8.encode('litert_crypto:enc:v1:$label'),
      );
      final macKey = await _hkdf.deriveKey(
        secretKey: master,
        info: utf8.encode('litert_crypto:mac:v1:$label'),
      );
      return (await encKey.extract(), await macKey.extract());
    } finally {
      master.destroy();
    }
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
