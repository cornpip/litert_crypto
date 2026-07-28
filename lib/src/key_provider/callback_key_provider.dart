import 'dart:typed_data';

import 'key_provider.dart';

/// Connects app-specific key logic (license file parsing, custom storage,
/// remote services, ...) through a callback.
///
/// The callback must return a fresh copy of the key material — see
/// [KeyProvider.getKey].
///
/// Example — extracting the key from a signed license file:
/// ```dart
/// final provider = CallbackKeyProvider((context) async {
///   final license = await License.loadAndVerify();
///   return license.modelKey;
/// });
/// ```
class CallbackKeyProvider implements KeyProvider {
  const CallbackKeyProvider(this._callback);

  final Future<Uint8List> Function(KeyContext context) _callback;

  @override
  Future<Uint8List> getKey(KeyContext context) => _callback(context);
}
