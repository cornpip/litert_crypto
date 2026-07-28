import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/services.dart' show rootBundle;
import 'package:tflite_flutter/tflite_flutter.dart';

import 'crypto/codec.dart';
import 'crypto/format.dart';
import 'decrypt_flow.dart';
import 'key_provider/key_provider.dart';

/// Loads a tflite_flutter [Interpreter] from an encrypted (LRTC) model.
///
/// A drop-in replacement for `Interpreter.fromAsset()` — it returns the same
/// [Interpreter] type, so your inference code stays unchanged.
///
/// ```dart
/// final interpreter = await EncryptedInterpreter.fromAsset(
///   'assets/tflite_model/model.tflite.enc',
///   keyProvider: EmbeddedKeyProvider.fromParts([partA, partB]),
/// );
/// ```
///
/// The plaintext model is never written to disk on any path — decryption
/// happens in memory only, and the resulting buffer goes straight into
/// [Interpreter.fromBuffer].
class EncryptedInterpreter {
  EncryptedInterpreter._();

  /// Loads an encrypted model from the asset bundle.
  static Future<Interpreter> fromAsset(
    String assetKey, {
    required KeyProvider keyProvider,
    InterpreterOptions? options,
  }) async {
    final data = await rootBundle.load(assetKey);
    final bytes =
        data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
    return fromBuffer(
      bytes,
      keyProvider: keyProvider,
      options: options,
      source: assetKey,
    );
  }

  /// Loads an encrypted model from a file (e.g. downloaded from a server).
  static Future<Interpreter> fromFile(
    File file, {
    required KeyProvider keyProvider,
    InterpreterOptions? options,
  }) async {
    return fromBuffer(
      await file.readAsBytes(),
      keyProvider: keyProvider,
      options: options,
      source: file.path,
    );
  }

  /// Loads an encrypted model from bytes.
  static Future<Interpreter> fromBuffer(
    Uint8List encryptedBytes, {
    required KeyProvider keyProvider,
    InterpreterOptions? options,
    String? source,
  }) async {
    final envelope = LrtcEnvelope.parse(encryptedBytes);
    final plain =
        await decryptWithProvider(envelope, keyProvider, source: source);
    try {
      return Interpreter.fromBuffer(
        plain,
        options: options ?? InterpreterOptions(),
      );
    } finally {
      // tflite_flutter's Model.fromBuffer copies the bytes into native memory,
      // so the Dart-side plaintext is dead weight the moment it returns —
      // zero it instead of leaving it for the garbage collector.
      LrtcCodec.wipe(plain);
    }
  }
}
