import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:litert_crypto/codec.dart';

/// Exercises the CLI's transformer mode the way `flutter build` does: a real
/// `dart run litert_crypto --input <tmp> --output <tmp>` subprocess, with the
/// temp-file naming the flutter tool uses (`<basename>-transformOutput<N><ext>`).
///
/// Spawning `dart run` compiles the BoringSSL host library on the first ever
/// run (needs cmake + a C compiler, NASM on Windows x64) — cached after that,
/// like every other host use of the package.
void main() {
  late Directory tempDir;
  late Uint8List key;
  late File plainFile;
  final plain = Uint8List.fromList(List.generate(4096, (i) => (i * 31 + 17) & 0xFF));

  Future<ProcessResult> runCli(List<String> args, {String? workingDirectory}) {
    return Process.run(
      'dart',
      ['run', 'litert_crypto', ...args],
      workingDirectory: workingDirectory ?? Directory.current.path,
    );
  }

  setUpAll(() {
    tempDir = Directory.systemTemp.createTempSync('litert_crypto_txf_test');
    key = Uint8List.fromList(List.generate(32, (i) => (i * 7 + 3) & 0xFF));
    File('${tempDir.path}/.secrets/model_master.key')
      ..createSync(recursive: true)
      ..writeAsStringSync(base64Encode(key));
    // No `key_parts_out`: the plain transformer tests exercise the
    // no-freshness-check path; the check itself has its own group below.
    File('${tempDir.path}/litert_crypto.yaml').writeAsStringSync(
      'litert_crypto:\n'
      '  key_file: .secrets/model_master.key\n',
    );
    // The flutter tool hands the transformer a temp copy named like this.
    plainFile = File('${tempDir.path}/demo.tflite-transformOutput0.tflite')
      ..writeAsBytesSync(plain);
  });

  tearDownAll(() => tempDir.deleteSync(recursive: true));

  group('transformer mode', () {
    test('encrypts, recovering the asset name as the label', () async {
      final out = '${tempDir.path}/demo.enc';
      final result = await runCli([
        '--input', plainFile.path,
        '--output', out,
        '--config', '${tempDir.path}/litert_crypto.yaml',
      ]);
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');

      final bytes = File(out).readAsBytesSync();
      final envelope = LrtcEnvelope.parse(bytes);
      // Not the temp name — the `-transformOutput<N><ext>` suffix is stripped.
      expect(envelope.label, 'demo.tflite');
      expect(envelope.keyId, 0);
      expect(await LrtcCodec.decrypt(bytes, key), plain);
    });

    test('honors --label and --key-id', () async {
      final out = '${tempDir.path}/labeled.enc';
      final result = await runCli([
        '--input', plainFile.path,
        '--output', out,
        '--label', 'opaque-name',
        '--key-id', '7',
        '--config', '${tempDir.path}/litert_crypto.yaml',
      ]);
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');

      final envelope = LrtcEnvelope.parse(File(out).readAsBytesSync());
      expect(envelope.label, 'opaque-name');
      expect(envelope.keyId, 7);
    });

    test('fails loudly when the key file is missing', () async {
      final orphan = Directory.systemTemp.createTempSync('litert_crypto_nokey');
      addTearDown(() => orphan.deleteSync(recursive: true));
      File('${orphan.path}/litert_crypto.yaml')
          .writeAsStringSync('litert_crypto:\n  key_file: .secrets/nope.key\n');

      final result = await runCli([
        '--input', plainFile.path,
        '--output', '${orphan.path}/out.enc',
        '--config', '${orphan.path}/litert_crypto.yaml',
      ]);
      expect(result.exitCode, isNot(0));
      expect(result.stderr, contains('keygen'));
    });

    test('fails when --output is missing', () async {
      final result = await runCli(['--input', plainFile.path]);
      expect(result.exitCode, isNot(0));
      expect(result.stderr, contains('--output'));
    });
  });

  group('pubspec.yaml as the config', () {
    // The CWD-walk fallback itself cannot be exercised from here: a fixture
    // pubspec.yaml placed on the walk would also hijack the spawned
    // `dart run`'s package resolution. The parsing path is identical for a
    // discovered and an explicit pubspec, so this pins the latter.
    test('a top-level `litert_crypto:` section works as the config', () async {
      final pubDir = Directory.systemTemp.createTempSync('litert_crypto_pub');
      addTearDown(() => pubDir.deleteSync(recursive: true));
      File('${pubDir.path}/.secrets/model_master.key')
        ..createSync(recursive: true)
        ..writeAsStringSync(base64Encode(key));
      final pubspec = File('${pubDir.path}/pubspec.yaml')
        ..writeAsStringSync(
          'name: cfg_probe\n'
          'environment:\n'
          "  sdk: ^3.10.0\n"
          '\n'
          'litert_crypto:\n'
          '  key_file: .secrets/model_master.key\n',
        );

      final out = '${pubDir.path}/pub.enc';
      final result = await runCli(
        ['--input', plainFile.path, '--output', out, '--config', pubspec.path],
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(
        await LrtcCodec.decrypt(File(out).readAsBytesSync(), key),
        plain,
      );
    });
  });

  group('keyparts and the freshness check', () {
    late Directory partsDir;
    late File partsKeyFile;
    late String partsConfig;

    setUpAll(() {
      partsDir = Directory.systemTemp.createTempSync('litert_crypto_parts');
      partsKeyFile = File('${partsDir.path}/.secrets/model_master.key')
        ..createSync(recursive: true)
        ..writeAsStringSync(base64Encode(key));
      partsConfig = '${partsDir.path}/litert_crypto.yaml';
      File(partsConfig).writeAsStringSync(
        'litert_crypto:\n'
        '  key_file: .secrets/model_master.key\n'
        '  key_parts_out: gen/model_master_key.dart\n',
      );
    });

    tearDownAll(() => partsDir.deleteSync(recursive: true));

    Future<ProcessResult> transform(String out) => runCli([
          '--input', plainFile.path,
          '--output', out,
          '--config', partsConfig,
        ]);

    test('the whole lifecycle: missing → generated → stale → regenerated',
        () async {
      // key_parts_out is configured but never generated: the transformer must
      // refuse — an app embedding no parts cannot decrypt what this encrypts.
      final missing = await transform('${partsDir.path}/a.enc');
      expect(missing.exitCode, isNot(0));
      expect(missing.stderr, contains('keyparts'));

      final generate = await runCli(['keyparts', '--config', partsConfig]);
      expect(generate.exitCode, 0,
          reason: '${generate.stdout}\n${generate.stderr}');
      final generated = File('${partsDir.path}/gen/model_master_key.dart');
      expect(generated.readAsStringSync(), contains('buildModelKeyProvider'));

      // Parts match the key: the transformer runs.
      final fresh = await transform('${partsDir.path}/b.enc');
      expect(fresh.exitCode, 0, reason: '${fresh.stdout}\n${fresh.stderr}');

      // Regenerating under the same key is a no-op.
      final noop = await runCli(['keyparts', '--config', partsConfig]);
      expect(noop.exitCode, 0);
      expect(noop.stdout, contains('already match'));

      // Rotate the key without rerunning keyparts: the transformer must
      // refuse again, naming the drift.
      final rotated =
          Uint8List.fromList(List.generate(32, (i) => (i * 13 + 5) & 0xFF));
      partsKeyFile.writeAsStringSync(base64Encode(rotated));
      final stale = await transform('${partsDir.path}/c.enc');
      expect(stale.exitCode, isNot(0));
      expect(stale.stderr, contains('stale'));

      // keyparts is a no-op only while the key is unchanged — after rotation
      // it regenerates, and the transformer accepts the pair again.
      final regenerate = await runCli(['keyparts', '--config', partsConfig]);
      expect(regenerate.exitCode, 0);
      expect(regenerate.stdout, contains('Wrote key parts'));
      final healed = await transform('${partsDir.path}/d.enc');
      expect(healed.exitCode, 0, reason: '${healed.stdout}\n${healed.stderr}');
    });

    test('a renamed key_parts_symbol regenerates even under the same key',
        () async {
      // Same key as the lifecycle test left behind — only the symbol changes.
      // The freshness check must treat that as stale, not "already match".
      File(partsConfig).writeAsStringSync(
        'litert_crypto:\n'
        '  key_file: .secrets/model_master.key\n'
        '  key_parts_out: gen/model_master_key.dart\n'
        '  key_parts_symbol: renamedKeyProvider\n',
      );

      final renamed = await runCli(['keyparts', '--config', partsConfig]);
      expect(renamed.exitCode, 0,
          reason: '${renamed.stdout}\n${renamed.stderr}');
      expect(renamed.stdout, contains('Wrote key parts'));
      expect(
        File('${partsDir.path}/gen/model_master_key.dart').readAsStringSync(),
        contains('KeyProvider renamedKeyProvider()'),
      );

      // And idempotent again under the new symbol.
      final noop = await runCli(['keyparts', '--config', partsConfig]);
      expect(noop.exitCode, 0);
      expect(noop.stdout, contains('already match'));
    });
  });
}
