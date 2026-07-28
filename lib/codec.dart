/// Flutter-free encryption core (entrypoint for CLI, servers, and scripts).
///
/// Use `package:litert_crypto/litert_crypto.dart` inside a Flutter app.
/// Use this entrypoint when handling the LRTC format on a plain Dart VM
/// (build scripts, backends) where Flutter is not available.
library;

export 'src/crypto/codec.dart';
export 'src/crypto/format.dart';
export 'src/exceptions.dart';
