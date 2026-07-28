/// Encrypt and load LiteRT (TensorFlow Lite / TFLite) models.
///
/// This package does not guarantee protection. It provides encryption tooling
/// and a key injection point ([KeyProvider]); the actual protection strength
/// is determined by how you manage your keys. Read the threat model in the
/// README before relying on it.
library;

export 'src/encrypted_model.dart';
export 'src/exceptions.dart';
export 'src/key_provider/callback_key_provider.dart';
export 'src/key_provider/embedded_key_provider.dart';
export 'src/key_provider/fallback_key_provider.dart';
export 'src/key_provider/key_cache.dart';
export 'src/key_provider/key_provider.dart';
export 'src/key_provider/remote_key_provider.dart';
