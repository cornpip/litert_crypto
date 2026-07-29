import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart' show constantTimeBytesEquality;

import '../exceptions.dart';
import 'format.dart';

/// Encrypts/decrypts the LRTC format: AES-256-CTR with encrypt-then-MAC
/// (HMAC-SHA256).
///
/// AES-GCM was measured ~3x slower on a 10 MB model in pure Dart (GHASH has
/// no hardware acceleration here), which matters because model decryption sits
/// on the app's load path. CTR + HMAC keeps authenticated encryption at a much
/// lower cost.
///
/// Encryption and MAC keys are derived from the caller's 32-byte key with
/// HKDF-SHA256, mixing in the envelope's label so that each model gets its own
/// working keys. Derived subkeys are destroyed as soon as they are used; the
/// caller's key buffer is left untouched (see [wipe] to clear it yourself).
///
/// Decryption drives the cipher through its synchronous state so it can convert
/// the model chunk by chunk inside a single buffer. That path is the pure-Dart
/// implementation: if you register a platform-backed one (`cryptography_flutter`)
/// it accelerates encryption but not decryption. Encryption — a build-time
/// step — still goes through whatever implementation is registered.
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

  /// Bytes processed per step when streaming over a model.
  ///
  /// Only bounds how long a single synchronous step runs; it does not change
  /// the output, so it can be tuned freely.
  static const int _chunkSize = 4 * 1024 * 1024;

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
  ///
  /// Allocates exactly one buffer, the size of the model: the ciphertext is
  /// copied into it and converted there. Handing the ciphertext to the cipher
  /// and taking its result instead would leave a second copy behind on any
  /// implementation that allocates its own output.
  static Future<Uint8List> decryptEnvelope(
    LrtcEnvelope envelope,
    Uint8List key,
  ) async {
    _checkKey(key);
    final (encKey, macKey) = await _deriveKeys(key, envelope.label);
    try {
      await _verify(envelope, macKey);
      final out = Uint8List(envelope.cipherText.length)
        ..setAll(0, envelope.cipherText);
      await _convertInPlace(out, envelope.iv, encKey);
      return out;
    } finally {
      encKey.destroy();
      macKey.destroy();
    }
  }

  /// Decrypts LRTC-formatted [bytes] **in place** and returns a view of the
  /// plaintext inside them, without allocating a second copy of the model.
  ///
  /// [bytes] is destroyed: the ciphertext region is overwritten with the
  /// plaintext, and the returned view shares that storage, so wiping either
  /// wipes both. [bytes] must therefore be a buffer you own and can write to —
  /// bytes you read from a file or received over the network, not a read-only
  /// view. Asset bundles hand out read-only buffers on some platforms (Android
  /// maps them straight out of the APK), so use [decrypt] for assets.
  ///
  /// Throws [DecryptionFailedException] on a wrong key or tampered data, in
  /// which case [bytes] is left untouched — the MAC is verified before a single
  /// byte is rewritten. Throws [UnsupportedError] if [bytes] is read-only.
  static Future<Uint8List> decryptInPlace(Uint8List bytes, Uint8List key) {
    return decryptEnvelopeInPlace(LrtcEnvelope.parse(bytes), key);
  }

  /// Decrypts an already-parsed [envelope] in place. See [decryptInPlace] for
  /// the ownership rules; [envelope] must be a view over the caller's buffer
  /// (which is what [LrtcEnvelope.parse] produces).
  static Future<Uint8List> decryptEnvelopeInPlace(
    LrtcEnvelope envelope,
    Uint8List key,
  ) async {
    _checkKey(key);
    final (encKey, macKey) = await _deriveKeys(key, envelope.label);
    try {
      // Encrypt-then-MAC still holds: the tag is checked over the intact
      // ciphertext before the rewrite starts, so a wrong key leaves the
      // caller's buffer as it was.
      await _verify(envelope, macKey);
      await _convertInPlace(envelope.cipherText, envelope.iv, encKey);
      return envelope.cipherText;
    } finally {
      encKey.destroy();
      macKey.destroy();
    }
  }

  /// Throws [DecryptionFailedException] unless [envelope]'s tag matches.
  static Future<void> _verify(LrtcEnvelope envelope, SecretKey macKey) async {
    final expected = await _tag(envelope.header, envelope.cipherText, macKey);
    if (!constantTimeBytesEquality.equals(expected, envelope.tag)) {
      throw const DecryptionFailedException(
        'MAC verification failed — wrong key or tampered data.',
      );
    }
  }

  /// XORs the keystream over [target], turning ciphertext into plaintext where
  /// it already sits. Callers must verify the MAC first.
  static Future<void> _convertInPlace(
    Uint8List target,
    Uint8List iv,
    SecretKey encKey,
  ) async {
    // toSync() pins the pure-Dart cipher, whose state XORs straight into the
    // buffer it is given. Platform-backed implementations are free to allocate
    // their own output instead, which is exactly what this avoids.
    final state = _cipher.toSync().newState();
    await state.initialize(
      isEncrypting: false,
      secretKey: encKey,
      nonce: iv,
    );

    for (var i = 0; i < target.length; i += _chunkSize) {
      final end = math.min(i + _chunkSize, target.length);
      final slice = Uint8List.sublistView(target, i, end);
      final converted = state.convertChunkSync(slice, possibleBuffer: slice);
      if (!identical(converted, slice)) {
        // Defensive: the contract allows an implementation to hand back its own
        // buffer instead of writing into ours.
        slice.setAll(0, converted);
      }
      // Give the event loop a turn between chunks; a large model otherwise
      // holds the isolate for seconds without interruption.
      await Future<void>.delayed(Duration.zero);
    }
    await state.convert(const <int>[], expectedMac: null);
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

  /// Computes the tag over `header || cipherText` without joining them.
  ///
  /// Concatenating first would allocate a second copy of the whole model, which
  /// is the dominant memory cost on large ones. The sink hashes incrementally,
  /// so only the 64-byte block buffer is held.
  static Future<Uint8List> _tag(
    Uint8List header,
    Uint8List cipherText,
    SecretKey macKey,
  ) async {
    final sink = await _hmac.newMacSink(secretKey: macKey);
    sink.add(header);
    for (var i = 0; i < cipherText.length; i += _chunkSize) {
      final end = math.min(i + _chunkSize, cipherText.length);
      sink.addSlice(cipherText, i, end, false);
    }
    sink.close();
    final mac = await sink.mac();
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
