import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/services.dart' show rootBundle;

import 'crypto/codec.dart';
import 'crypto/format.dart';
import 'decrypt_flow.dart';
import 'key_provider/key_provider.dart';

/// Builds a runtime object from decrypted model bytes.
///
/// Pass your inference runtime's buffer constructor — `Interpreter.fromBuffer`
/// for LiteRT/TFLite, or anything else that accepts the raw model.
typedef ModelBuilder<T> = FutureOr<T> Function(Uint8List modelBytes);

/// Loads an encrypted (LRTC) model and hands the plaintext to your runtime.
///
/// This package deliberately depends on no inference runtime: you supply the
/// [ModelBuilder], so the same code works with `flutter_litert`,
/// `tflite_flutter`, or anything else.
///
/// ```dart
/// final interpreter = await EncryptedModel.fromAsset(
///   'assets/tflite_model/model.tflite.enc',
///   keyProvider: EmbeddedKeyProvider.fromParts([partA, partB]),
///   build: Interpreter.fromBuffer,
/// );
/// ```
///
/// The plaintext is never written to disk, and the buffer is zeroed as soon as
/// [ModelBuilder] returns — runtimes copy the model into their own memory, so
/// holding on to the Dart buffer only leaves plaintext lying in the heap. If
/// your runtime keeps a reference to the buffer instead of copying it, use
/// [decryptAsset] and manage the lifetime yourself.
class EncryptedModel {
  EncryptedModel._();

  /// Loads an encrypted model from the asset bundle.
  static Future<T> fromAsset<T>(
    String assetKey, {
    required KeyProvider keyProvider,
    required ModelBuilder<T> build,
  }) async {
    return fromBuffer(
      await _loadAsset(assetKey),
      keyProvider: keyProvider,
      build: build,
      source: assetKey,
    );
  }

  /// Loads an encrypted model from a file (e.g. downloaded from a server).
  static Future<T> fromFile<T>(
    File file, {
    required KeyProvider keyProvider,
    required ModelBuilder<T> build,
  }) async {
    return fromBuffer(
      await file.readAsBytes(),
      keyProvider: keyProvider,
      build: build,
      source: file.path,
    );
  }

  /// Loads an encrypted model from bytes.
  static Future<T> fromBuffer<T>(
    Uint8List encryptedBytes, {
    required KeyProvider keyProvider,
    required ModelBuilder<T> build,
    String? source,
  }) async {
    final plain = await decryptWithProvider(
      LrtcEnvelope.parse(encryptedBytes),
      keyProvider,
      source: source,
    );
    try {
      return await build(plain);
    } finally {
      LrtcCodec.wipe(plain);
    }
  }

  /// Decrypts an encrypted asset and returns the plaintext bytes.
  ///
  /// Use this when the runtime needs the buffer to stay alive. **You own the
  /// result**: zero it with [LrtcCodec.wipe] once the runtime has copied it,
  /// and never write it to disk.
  static Future<Uint8List> decryptAsset(
    String assetKey, {
    required KeyProvider keyProvider,
  }) async {
    return decryptBuffer(
      await _loadAsset(assetKey),
      keyProvider: keyProvider,
      source: assetKey,
    );
  }

  /// Decrypts encrypted bytes and returns the plaintext. See [decryptAsset]
  /// for the ownership rules.
  static Future<Uint8List> decryptBuffer(
    Uint8List encryptedBytes, {
    required KeyProvider keyProvider,
    String? source,
  }) {
    return decryptWithProvider(
      LrtcEnvelope.parse(encryptedBytes),
      keyProvider,
      source: source,
    );
  }

  static Future<Uint8List> _loadAsset(String assetKey) async {
    final data = await rootBundle.load(assetKey);
    return data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
  }
}
