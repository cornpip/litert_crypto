import 'dart:convert';
import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart';

import '../exceptions.dart';
import 'format.dart';

/// Encrypts/decrypts the LRTC format: AES-256-GCM with the envelope header as
/// additional authenticated data.
///
/// Backed by BoringSSL through `package:webcrypto` (dart:ffi), so AES and
/// GHASH run on the CPU's crypto instructions where they exist — which is
/// every ARMv8 phone. The whole seal/open is a single native call.
///
/// The format version was bumped to 2 over the switch from the pure-Dart
/// 0.1.0 engine (AES-CTR + HMAC-SHA256); v1 files must be re-encrypted.
///
/// The working key is derived from the caller's 32-byte key with HKDF-SHA256,
/// mixing in the envelope's label so that each model gets its own working
/// key. Derived key bytes are zeroed as soon as they are used; the caller's
/// key buffer is left untouched (see [wipe] to clear it yourself). The
/// BoringSSL-side key schedule lives in native memory until the key object is
/// garbage collected — that copy is out of our hands, which the README's
/// threat model already concedes for anything in process memory.
class LrtcCodec {
  LrtcCodec._();

  /// Required length of the master key supplied by a `KeyProvider`.
  static const int keyLength = 32;

  /// GCM tag length in bits, pinned into the format ([LrtcEnvelope.tagLength]).
  static const int _tagBits = LrtcEnvelope.tagLength * 8;

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
    final iv = Uint8List(LrtcEnvelope.ivLength);
    fillRandomBytes(iv);
    final header = LrtcEnvelope.buildHeader(
      version: LrtcEnvelope.currentVersion,
      keyId: keyId,
      label: label,
      iv: iv,
    );

    final encKey = await _deriveKey(key, label);
    try {
      final aes = await AesGcmSecretKey.importRawKey(encKey);
      final sealed = await aes.encryptBytes(
        plain,
        iv,
        additionalData: header,
        tagLength: _tagBits,
      );
      return LrtcEnvelope(
        version: LrtcEnvelope.currentVersion,
        keyId: keyId,
        label: label,
        header: header,
        iv: iv,
        sealed: sealed,
      ).serialize();
    } finally {
      wipe(encKey);
    }
  }

  /// Decrypts LRTC-formatted [bytes] and returns the plaintext.
  ///
  /// Throws [DecryptionFailedException] on a wrong key or tampered data.
  static Future<Uint8List> decrypt(Uint8List bytes, Uint8List key) {
    return decryptEnvelope(LrtcEnvelope.parse(bytes), key);
  }

  /// Decrypts an already-parsed [envelope].
  ///
  /// The ciphertext is read where it sits — works on read-only asset buffers.
  /// One model-sized Dart buffer is allocated for the result; BoringSSL also
  /// holds native copies of input and output for the duration of the call,
  /// freed deterministically when it returns.
  static Future<Uint8List> decryptEnvelope(
    LrtcEnvelope envelope,
    Uint8List key,
  ) async {
    _checkKey(key);
    final encKey = await _deriveKey(key, envelope.label);
    try {
      final aes = await AesGcmSecretKey.importRawKey(encKey);
      return await aes.decryptBytes(
        envelope.sealed,
        envelope.iv,
        additionalData: envelope.header,
        tagLength: _tagBits,
      );
    } on OperationError {
      // BoringSSL refuses the open when the tag does not verify — the GCM
      // equivalent of a MAC failure, checked over header and ciphertext both.
      throw const DecryptionFailedException(
        'Authentication failed — wrong key or tampered data.',
      );
    } finally {
      wipe(encKey);
    }
  }

  /// Overwrites [bytes] with zeros.
  ///
  /// Used on plaintext and key material once it is no longer needed, so it does
  /// not linger in the heap until garbage collection.
  static void wipe(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);

  /// Derives the working key for [label].
  ///
  /// HKDF-SHA256 with an empty salt (RFC 5869's zero-filled default). The
  /// caller's [key] is not modified — clearing it is the caller's call (the
  /// loader does exactly that once a model is decrypted).
  static Future<Uint8List> _deriveKey(Uint8List key, String label) async {
    final master = await HkdfSecretKey.importRawKey(key);
    return master.deriveBits(
      keyLength * 8,
      Hash.sha256,
      const [],
      utf8.encode('litert_crypto:enc:v2:$label'),
    );
  }

  static void _checkKey(Uint8List key) {
    if (key.length != keyLength) {
      throw KeyUnavailableException(
        'Expected a $keyLength-byte key, got ${key.length} bytes.',
      );
    }
  }
}
