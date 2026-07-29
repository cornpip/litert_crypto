import 'dart:isolate';
import 'dart:typed_data';

import 'crypto/codec.dart';

/// Decrypts [encryptedBytes] on a worker isolate and returns the plaintext.
///
/// Decryption is CPU-bound and scales with model size. BoringSSL makes it
/// fast, but on a large model it is still tens to hundreds of milliseconds of
/// solid work — run inline, that is dropped frames; here it costs the calling
/// isolate nothing.
///
/// The ciphertext moves over as [TransferableTypedData] — one copy, then the
/// worker owns the bytes. The plaintext comes back through `Isolate.run`,
/// which returns its result by transferring it rather than copying it.
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
      return await LrtcCodec.decrypt(owned, keyCopy);
    } finally {
      LrtcCodec.wipe(keyCopy);
      LrtcCodec.wipe(owned);
    }
  });
}
