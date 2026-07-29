import 'dart:isolate';
import 'dart:typed_data';

import 'crypto/codec.dart';

/// Decrypts [encryptedBytes] on a worker isolate and returns the plaintext.
///
/// Decryption is CPU-bound and scales with model size — a 68 MB model takes
/// about three seconds on a mid-range phone. Run inline, that is three seconds
/// in which the calling isolate renders nothing.
///
/// Neither buffer is copied more than once on the way:
///
/// * the ciphertext moves over as [TransferableTypedData], so the worker owns
///   writable bytes and can decrypt in place — no second full-size buffer;
/// * the plaintext comes back through `Isolate.run`, which returns its result
///   by transferring it rather than copying it.
///
/// The key is resolved by the caller and only its bytes travel, so providers
/// that do I/O (`RemoteKeyProvider`) keep running on the calling isolate.
Future<Uint8List> decryptOnIsolate(
  Uint8List encryptedBytes,
  Uint8List key,
) async {
  final transferred = TransferableTypedData.fromList([encryptedBytes]);
  final keyCopy = Uint8List.fromList(key);

  return Isolate.run(() async {
    final owned = transferred.materialize().asUint8List();
    try {
      return await LrtcCodec.decryptInPlace(owned, keyCopy);
    } finally {
      LrtcCodec.wipe(keyCopy);
    }
  });
}
