import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:litert_crypto/codec.dart';
import 'package:yaml/yaml.dart';

const _defaultKeyPath = '.secrets/model_master.key';
const _configFileName = 'litert_crypto.yaml';
const _defaultKeyPartsSymbol = 'buildModelKeyProvider';
const _fingerprintMarker = 'key-fingerprint: ';

Future<void> main(List<String> arguments) async {
  final parser = ArgParser()
    ..addCommand(
      'keygen',
      ArgParser()..addOption('out', help: 'Key file path', defaultsTo: _defaultKeyPath),
    )
    ..addCommand(
      'init',
      ArgParser()
        ..addOption('out', help: 'Config path', defaultsTo: _configFileName),
    )
    ..addCommand(
      'encrypt',
      ArgParser()
        ..addOption('key', help: 'Key file path (base64, from keygen)')
        ..addOption('in', help: 'Plaintext model path')
        ..addOption('out', help: 'Encrypted output path')
        ..addOption('key-id', help: 'uint16 key id for rotation', defaultsTo: '0')
        ..addOption('label',
            help: 'Model label bound into key derivation '
                '(defaults to the output file name)')
        ..addOption('config',
            help: 'Config path (default: nearest $_configFileName '
                'at or above the working directory)'),
    );

  final ArgResults results;
  try {
    results = parser.parse(arguments);
  } on FormatException catch (e) {
    _fail('${e.message}\n\n${_usage(parser)}');
  }

  final command = results.command;
  if (command == null) {
    _fail(_usage(parser));
  }

  switch (command.name) {
    case 'init':
      await _init(command);
    case 'keygen':
      await _keygen(command);
    case 'encrypt':
      await _encrypt(command);
  }
}

String _usage(ArgParser parser) => '''
litert_crypto — encrypt LiteRT (tflite) models

Usage:
  dart run litert_crypto init [--out $_configFileName]
  dart run litert_crypto keygen [--out $_defaultKeyPath]
  dart run litert_crypto encrypt [--config <path>]
  dart run litert_crypto encrypt --key <keyfile> --in <model.tflite> --out <model.tflite.enc> [--key-id 0] [--label name]

Without --key/--in/--out, encrypt reads $_configFileName — the one given by
--config, otherwise the nearest one at or above the working directory. Paths
inside it are relative to the config file. `init` writes a starter config.
''';

Future<void> _keygen(ArgResults args) async {
  final outPath = args['out'] as String;
  final file = File(outPath);
  if (file.existsSync()) {
    _fail('Refusing to overwrite existing key file: $outPath');
  }
  final random = Random.secure();
  final key = Uint8List.fromList(
    List<int>.generate(LrtcCodec.keyLength, (_) => random.nextInt(256)),
  );
  file.parent.createSync(recursive: true);
  file.writeAsStringSync(base64Encode(key));
  _restrictToOwner(outPath);
  stdout.writeln('Wrote ${LrtcCodec.keyLength}-byte key: $outPath');
  stdout.writeln('Keep it out of version control (add to .gitignore).');
}

/// Best-effort `chmod 600`: a master key file must not be world-readable,
/// which is what the default umask would leave it as.
void _restrictToOwner(String path) {
  if (Platform.isWindows) return;
  final result = Process.runSync('chmod', ['600', path]);
  if (result.exitCode != 0) {
    stdout.writeln(
      'Warning: could not restrict permissions on $path '
      '(chmod exited with ${result.exitCode}) — do it manually.',
    );
  }
}

Future<void> _encrypt(ArgResults args) async {
  final direct = args['in'] != null || args['out'] != null || args['key'] != null;
  if (direct) {
    final input = args['in'] as String?;
    final output = args['out'] as String?;
    final keyPath = args['key'] as String?;
    if (input == null || output == null || keyPath == null) {
      _fail('encrypt requires --key, --in and --out (or a $_configFileName).');
    }
    final keyId = _parseKeyId(args['key-id'] as String, '--key-id');
    await _encryptOne(keyPath, input, output, keyId, args['label'] as String?);
    return;
  }

  // Config file mode.
  final configFile = _findConfig(args['config'] as String?);
  final configDir = configFile.parent.path;

  final doc = loadYaml(configFile.readAsStringSync());
  final section = doc is YamlMap ? doc['litert_crypto'] : null;
  if (section is! YamlMap) {
    _fail('${configFile.path} must contain a top-level `litert_crypto:` section.');
  }

  // Paths are relative to the config file, so the command works from any
  // subdirectory of the project.
  String at(String path) => _resolve(configDir, path);

  final keyPath = at(section['key_file'] as String? ?? _defaultKeyPath);

  // Keep the embedded key source in step with the key file, so the two can
  // never drift apart.
  final keyPartsOut = section['key_parts_out'] as String?;
  if (keyPartsOut != null) {
    await _writeKeyParts(
      keyPath,
      at(keyPartsOut),
      section['key_parts_symbol'] as String? ?? _defaultKeyPartsSymbol,
    );
  }

  final models = section['models'];
  if (models is! YamlList || models.isEmpty) {
    _fail('`litert_crypto.models` must be a non-empty list of {src, out}.');
  }
  for (final entry in models) {
    if (entry is! YamlMap || entry['src'] == null || entry['out'] == null) {
      _fail('Each model entry needs `src` and `out`.');
    }
    final keyId =
        _parseKeyId('${entry['key_id'] ?? 0}', '`key_id` for ${entry['src']}');
    await _encryptOne(
      keyPath,
      at(entry['src'] as String),
      at(entry['out'] as String),
      keyId,
      entry['label'] as String?,
    );
  }
}

/// Key ids identify keys across rotations, so a typo must not silently
/// become "key 0" — that mislabels the file for every later key lookup.
int _parseKeyId(String raw, String what) {
  final value = int.tryParse(raw);
  if (value == null || value < 0 || value > 0xFFFF) {
    _fail('Invalid $what: "$raw" (expected an integer 0-65535).');
  }
  return value;
}

/// Locates the config: an explicit `--config`, otherwise the nearest
/// `litert_crypto.yaml` at or above the working directory.
File _findConfig(String? explicitPath) {
  if (explicitPath != null) {
    final file = File(explicitPath);
    if (!file.existsSync()) _fail('Config not found: $explicitPath');
    return file;
  }

  return _findConfigOrNull(Directory.current) ??
      _fail(
        'No arguments and no $_configFileName found here or in any parent '
        'directory.\n\nCreate one with:  dart run litert_crypto init',
      );
}

/// Nearest config at or above [start], or null when there is none.
File? _findConfigOrNull(Directory start) {
  var dir = start;
  while (true) {
    final candidate = File('${dir.path}/$_configFileName');
    if (candidate.existsSync()) return candidate;
    final parent = dir.parent;
    if (parent.path == dir.path) return null;
    dir = parent;
  }
}

String _resolve(String baseDir, String path) {
  final isAbsolute = path.startsWith('/') || RegExp(r'^[A-Za-z]:').hasMatch(path);
  return isAbsolute ? path : '$baseDir/$path';
}

/// Writes a starter config next to the project so `encrypt` has something to
/// read.
Future<void> _init(ArgResults args) async {
  final outPath = args['out'] as String;
  final file = File(outPath);
  if (file.existsSync()) {
    _fail('Refusing to overwrite existing config: $outPath');
  }

  if (file.uri.pathSegments.last != _configFileName) {
    // encrypt only auto-discovers files named litert_crypto.yaml.
    stdout
      ..writeln('Note: encrypt will not find this file on its own — pass it')
      ..writeln('explicitly:  dart run litert_crypto encrypt --config $outPath')
      ..writeln('');
  } else {
    // A config above this one would otherwise be shadowed silently, since
    // `encrypt` takes the nearest match.
    final existing = _findConfigOrNull(file.absolute.parent.parent);
    if (existing != null) {
      stdout
        ..writeln('Note: a config already exists at ${existing.path}.')
        ..writeln('Once written, $outPath takes precedence for commands run')
        ..writeln('from its directory or below, because encrypt uses the')
        ..writeln('nearest one. Cancel with Ctrl-C if you meant to use the')
        ..writeln('existing config instead.')
        ..writeln('');
    }
  }

  file.parent.createSync(recursive: true);
  file.writeAsStringSync('''
# litert_crypto — model encryption config.
# Paths are relative to this file. Run: dart run litert_crypto encrypt
litert_crypto:
  # Written by `dart run litert_crypto keygen`. Never commit it.
  key_file: $_defaultKeyPath

  # Optional: generated Dart source rebuilding the key from XOR parts, for
  # EmbeddedKeyProvider. Remove this line if the key does not ship with the app
  # (license file, server, secure storage) — see the README on where keys live.
  key_parts_out: lib/model_master_key.dart

  models:
    # `src` stays out of your assets so the plaintext is never bundled;
    # register only `out` as a Flutter asset.
    - src: models_src/model.tflite
      out: assets/tflite_model/model.tflite.enc
      # label: opaque-name   # defaults to the out file name; stored in the
      #                      # clear inside the encrypted file
      # key_id: 0            # bump when rotating keys
''');

  stdout
    ..writeln('Wrote $outPath')
    ..writeln('')
    ..writeln('Next:')
    ..writeln('  1. dart run litert_crypto keygen')
    ..writeln('  2. add ${File(_defaultKeyPath).parent.path}/ to .gitignore')
    ..writeln('  3. move your models under models_src/ and edit the config')
    ..writeln('  4. dart run litert_crypto encrypt');
}

/// Writes Dart source that rebuilds the key from XOR-combined parts.
///
/// Regenerating is a no-op while the key is unchanged: the file records a
/// fingerprint of the key it was built from, so repeated `encrypt` runs do not
/// churn the source tree.
Future<void> _writeKeyParts(
  String keyPath,
  String outPath,
  String symbol,
) async {
  final key = _readKey(keyPath);
  final fingerprint = _fingerprint(key);
  final outFile = File(outPath);

  if (outFile.existsSync() &&
      outFile.readAsStringSync().contains('$_fingerprintMarker$fingerprint')) {
    stdout.writeln('Key parts already match $keyPath: $outPath');
    return;
  }

  final random = Random.secure();
  final partA = List<int>.generate(key.length, (_) => random.nextInt(256));
  final partB = List<int>.generate(key.length, (i) => key[i] ^ partA[i]);

  outFile.parent.createSync(recursive: true);
  outFile.writeAsStringSync('''
// GENERATED by `dart run litert_crypto encrypt` — do not edit by hand.
// Regenerate after changing the key; the fingerprint below tracks which key
// these parts belong to.
//
// The key ships inside the app, so this is the weakest tier of protection: it
// stops extraction from the distributed artifact, not reverse engineering.
// See the "Where the key lives" section of the litert_crypto README.
//
// $_fingerprintMarker$fingerprint

import 'dart:typed_data';

import 'package:litert_crypto/litert_crypto.dart';

/// Rebuilds the model key from parts that are combined at runtime, so the key
/// never appears as a literal in the binary.
KeyProvider $symbol() => EmbeddedKeyProvider.fromParts([_partA, _partB]);

final Uint8List _partA = Uint8List.fromList(const [
${_formatBytes(partA)}
]);

final Uint8List _partB = Uint8List.fromList(const [
${_formatBytes(partB)}
]);
''');
  stdout.writeln('Wrote key parts for $keyPath -> $outPath');
}

String _formatBytes(List<int> bytes) {
  final rows = <String>[];
  for (var i = 0; i < bytes.length; i += 8) {
    final slice = bytes
        .skip(i)
        .take(8)
        .map((b) => '0x${b.toRadixString(16).padLeft(2, '0')}');
    rows.add('  ${slice.join(', ')},');
  }
  return rows.join('\n');
}

/// Short digest identifying a key, used to detect a stale generated file.
String _fingerprint(Uint8List key) {
  var hash = 0x811c9dc5;
  for (final byte in key) {
    hash = ((hash ^ byte) * 0x01000193) & 0xFFFFFFFF;
  }
  return hash.toRadixString(16).padLeft(8, '0');
}

Uint8List _readKey(String keyPath) {
  final keyFile = File(keyPath);
  if (!keyFile.existsSync()) {
    _fail(
      'Key file not found: $keyPath (run `dart run litert_crypto keygen` first).',
    );
  }
  return Uint8List.fromList(base64Decode(keyFile.readAsStringSync().trim()));
}

Future<void> _encryptOne(
  String keyPath,
  String inputPath,
  String outputPath,
  int keyId,
  String? label,
) async {
  final key = _readKey(keyPath);

  final inputFile = File(inputPath);
  if (!inputFile.existsSync()) {
    _fail('Input model not found: $inputPath');
  }
  final plain = inputFile.readAsBytesSync();

  // Default to the output name rather than the source name: the label is
  // stored in the clear, and the output name is already visible in the shipped
  // bundle, so this leaks nothing new. Distinct outputs also keep labels
  // distinct, which is all key derivation needs.
  final effectiveLabel = label ?? outputPath.split(RegExp(r'[/\\]')).last;
  final encrypted = await LrtcCodec.encrypt(
    plain,
    key,
    keyId: keyId,
    label: effectiveLabel,
  );
  final outFile = File(outputPath);
  outFile.parent.createSync(recursive: true);
  outFile.writeAsBytesSync(encrypted);
  stdout.writeln(
    'Encrypted $inputPath (${plain.length} bytes) '
    '-> $outputPath (${encrypted.length} bytes, '
    'keyId=$keyId, label="$effectiveLabel")',
  );
}

Never _fail(String message) {
  stderr.writeln(message);
  exit(1);
}
