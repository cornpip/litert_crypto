import 'dart:typed_data';

import 'crypto/codec.dart';
import 'crypto/format.dart';
import 'key_provider/key_provider.dart';

/// Asks [keyProvider] for a key, decrypts [envelope] with it, and zeroes the
/// key buffer afterwards.
///
/// This is the flow the loader uses: it owns the key from the moment the
/// provider hands it over, so it can clear it as soon as the model is out.
/// Providers must therefore return a fresh copy of their key material.
Future<Uint8List> decryptWithProvider(
  LrtcEnvelope envelope,
  KeyProvider keyProvider, {
  String? source,
}) async {
  final key = await keyProvider.getKey(
    KeyContext(keyId: envelope.keyId, source: source, label: envelope.label),
  );
  try {
    return await LrtcCodec.decryptEnvelope(envelope, key);
  } finally {
    LrtcCodec.wipe(key);
  }
}
