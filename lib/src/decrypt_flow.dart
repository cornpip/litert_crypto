import 'dart:typed_data';

import 'crypto/codec.dart';
import 'crypto/format.dart';
import 'isolate_decrypt.dart';
import 'key_provider/key_provider.dart';

/// Asks [keyProvider] for a key, decrypts [envelope] with it, and zeroes the
/// key buffer afterwards.
///
/// This is the flow the loader uses: it owns the key from the moment the
/// provider hands it over, so it can clear it as soon as the model is out.
/// Providers must therefore return a fresh copy of their key material.
///
/// With [inIsolate] the decryption runs on a worker isolate, leaving the
/// calling isolate free to render. The key is always resolved here, so
/// providers that do I/O are unaffected. [encryptedBytes] is required for that
/// path: the worker needs the whole envelope, not views into it.
Future<Uint8List> decryptWithProvider(
  LrtcEnvelope envelope,
  KeyProvider keyProvider, {
  String? source,
  bool inIsolate = false,
  Uint8List? encryptedBytes,
}) async {
  assert(
    !inIsolate || encryptedBytes != null,
    'inIsolate needs encryptedBytes — the worker decrypts the whole envelope, '
    'not the views this one holds. Without it the decryption silently runs on '
    'the calling isolate.',
  );

  final key = await keyProvider.getKey(
    KeyContext(keyId: envelope.keyId, source: source, label: envelope.label),
  );
  try {
    if (inIsolate && encryptedBytes != null) {
      return await decryptOnIsolate(encryptedBytes, key);
    }
    return await LrtcCodec.decryptEnvelope(envelope, key);
  } finally {
    LrtcCodec.wipe(key);
  }
}
