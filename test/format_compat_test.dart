import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:litert_crypto/codec.dart';

/// A v2 envelope produced by the 0.2.0 BoringSSL engine, checked in verbatim.
/// This pins the format — key derivation info string, GCM parameters, header
/// layout — so a later refactor cannot silently change the bytes and orphan
/// every model users have already encrypted.
///
/// Key: (i * 7 + 3) & 0xFF. Payload: 4109 bytes of (i * 31 + 17) & 0xFF —
/// deliberately not block-aligned. keyId 7, label 'compat-fixture'.
final Uint8List _v2Envelope = base64Decode(
    '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'
    'Uw==',
);

Uint8List _key() =>
    Uint8List.fromList(List.generate(32, (i) => (i * 7 + 3) & 0xFF));

Uint8List _payload() =>
    Uint8List.fromList(List.generate(4109, (i) => (i * 31 + 17) & 0xFF));

void main() {
  test('decrypts a pinned v2 envelope byte for byte', () async {
    final envelope = LrtcEnvelope.parse(_v2Envelope);
    expect(envelope.keyId, 7);
    expect(envelope.label, 'compat-fixture');
    expect(envelope.plainLength, 4109);

    final plain = await LrtcCodec.decrypt(_v2Envelope, _key());
    expect(plain, equals(_payload()));
  });

  test('wrong key fails cleanly on the fixture', () async {
    final wrong = Uint8List.fromList(_key().reversed.toList());
    expect(
      () => LrtcCodec.decrypt(_v2Envelope, wrong),
      throwsA(isA<DecryptionFailedException>()),
    );
  });

  test('v1 files are refused with a re-encrypt hint', () async {
    // Magic + version 1 + keyId + empty label: enough header for the version
    // check, which is all a 0.1.0 file gets to before being turned away.
    final v1 = Uint8List.fromList([0x4C, 0x52, 0x54, 0x43, 1, 0, 0, 0]);
    expect(
      () => LrtcEnvelope.parse(v1),
      throwsA(
        isA<InvalidFormatException>().having(
          (e) => e.message,
          'message',
          contains('re-encrypt'),
        ),
      ),
    );
  });
}
