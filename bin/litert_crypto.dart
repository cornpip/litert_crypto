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
    // Transformer mode — no subcommand. `flutter build` invokes
    // `dart run litert_crypto --input <tmp> --output <tmp> [args...]` for
    // each asset that lists this package under `transformers:`.
    ..addOption('input', help: 'Plaintext asset path (passed by flutter build)')
    ..addOption('output', help: 'Encrypted output path (passed by flutter build)')
    ..addOption('label',
        help: 'Model label bound into key derivation '
            '(defaults to the asset file name)')
    ..addOption('key-id', help: 'uint16 key id for rotation', defaultsTo: '0')
    ..addOption('config',
        help: 'Config path (default: nearest $_configFileName '
            'at or above the working directory)')
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
      'keyparts',
      ArgParser()
        ..addOption('config',
            help: 'Config path (default: nearest $_configFileName '
                'at or above the working directory)'),
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
    if (results['input'] != null || results['output'] != null) {
      await _transform(results);
      return;
    }
    _fail(_usage(parser));
  }

  switch (command.name) {
    case 'init':
      await _init(command);
    case 'keygen':
      await _keygen(command);
    case 'keyparts':
      await _keyparts(command);
    case 'encrypt':
      await _encrypt(command);
  }
}

String _usage(ArgParser parser) => '''
litert_crypto — encrypt LiteRT (tflite) models

Usage:
  dart run litert_crypto init [--out $_configFileName]
  dart run litert_crypto keygen [--out $_defaultKeyPath]
  dart run litert_crypto keyparts [--config <path>]
  dart run litert_crypto encrypt [--config <path>]
  dart run litert_crypto encrypt --key <keyfile> --in <model.tflite> --out <model.tflite.enc> [--key-id 0] [--label name]
  dart run litert_crypto --input <plain> --output <encrypted> [--label name] [--key-id 0] [--config <path>]

Without --key/--in/--out, encrypt reads the config — the file given by
--config, otherwise the nearest $_configFileName at or above the working
directory, otherwise a top-level `litert_crypto:` section in the nearest
pubspec.yaml (a dedicated file wins when both exist). Paths inside it are
relative to the file it lives in. `init` writes a starter config.

The --input/--output form is transformer mode: `flutter build` calls it for
each asset that lists this package under `transformers:` in pubspec.yaml, so
the bundle carries ciphertext while the plaintext stays in your source tree.
`keyparts` (re)generates the `key_parts_out` Dart source from the config —
transformer setups need it because they never run `encrypt`.
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
  final (configFile, section) = _loadConfig(args['config'] as String?);
  final configDir = configFile.parent.path;

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
    _fail('`litert_crypto.models` must be a non-empty list of {src, out}.\n'
        'If your assets are encrypted by the build instead (transformer mode),\n'
        '`encrypt` has nothing to do — `keyparts` regenerates the key source.');
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

/// Transformer mode — the flutter tool runs this from the app's project root
/// for every asset that lists this package under `transformers:` in
/// pubspec.yaml, so config discovery works exactly as it does for `encrypt`.
Future<void> _transform(ArgResults args) async {
  final input = args['input'] as String?;
  final output = args['output'] as String?;
  if (input == null || output == null) {
    _fail('Transformer mode needs both --input and --output.');
  }

  final explicitConfig = args['config'] as String?;
  final configFile = explicitConfig != null
      ? _findConfig(explicitConfig)
      : _findConfigOrNull(Directory.current) ??
          _findPubspecConfigOrNull(Directory.current) ??
          _fail(
            'No config found: no $_configFileName and no `litert_crypto:` '
            'section in pubspec.yaml, searched from the project root upward. '
            'The transformer reads `key_file` from one of them.\n'
            '\n'
            'Quickest fix — add a top-level section to pubspec.yaml:\n'
            '\n'
            '  litert_crypto:\n'
            '    key_file: $_defaultKeyPath\n'
            '\n'
            'and create the key if you have none yet:  '
            'dart run litert_crypto keygen\n'
            '\n'
            '(`dart run litert_crypto init` writes an annotated config file '
            'instead; a config\n'
            "elsewhere is reached with args: ['--config', ...] on the "
            'transformer entry.)',
          );
  final section = _readConfigSection(configFile);
  final configDir = configFile.parent.path;
  final keyPath = _resolve(
    configDir,
    section['key_file'] as String? ?? _defaultKeyPath,
  );

  // `key_parts_out` set means the app embeds this key — refuse to encrypt
  // with a key the committed parts cannot rebuild.
  final keyPartsOut = section['key_parts_out'] as String?;
  if (keyPartsOut != null) {
    _requireFreshKeyParts(keyPath, _resolve(configDir, keyPartsOut));
  }

  final keyId = _parseKeyId(args['key-id'] as String, '--key-id');
  // The input is a temp copy named `<asset>-transformOutput<N><ext>`, so the
  // usual label default (the output file name) would bake a meaningless temp
  // name into the envelope. Recover the asset's own name instead.
  final label = args['label'] as String? ?? _originalBasename(input);
  await _encryptOne(keyPath, input, output, keyId, label);
}

/// Fails the build when the generated key parts do not match the key the
/// transformer is about to encrypt with (`keygen` ran, `keyparts` did not) —
/// otherwise the drift surfaces only as a decryption failure at app runtime.
///
/// Failing is the only channel: the flutter tool shows a transformer's output
/// solely when it exits non-zero, so a warning would never reach anyone.
/// The check is read-only, which keeps parallel per-asset transforms safe.
void _requireFreshKeyParts(String keyPath, String keyPartsPath) {
  final partsFile = File(keyPartsPath);
  final expected = _fingerprint(_readKey(keyPath));
  if (partsFile.existsSync() &&
      partsFile.readAsStringSync().contains('$_fingerprintMarker$expected')) {
    return;
  }
  _fail(
    partsFile.existsSync()
        ? 'Key parts are stale: $keyPartsPath was generated from a different '
            'key than $keyPath.\n'
            'Run `dart run litert_crypto keyparts` and rebuild — this build '
            'would embed a key that cannot decrypt its own assets.'
        : 'Key parts not generated yet: $keyPartsPath does not exist.\n'
            'Run `dart run litert_crypto keyparts`, or remove `key_parts_out` '
            'from the config if the key does not ship inside the app.',
  );
}

/// The asset's own file name, recovered from the temp copy the flutter tool
/// hands a transformer (`<basename>-transformOutput<N><ext>`). Left as-is
/// when the pattern is absent (direct invocation).
String _originalBasename(String inputPath) {
  final name = inputPath.split(RegExp(r'[/\\]')).last;
  return name.replaceFirst(RegExp(r'-transformOutput\d+(\.[^.]*)?$'), '');
}

/// (Re)generates the `key_parts_out` source from the config — the standalone
/// path for transformer setups, which never run `encrypt`.
Future<void> _keyparts(ArgResults args) async {
  final (configFile, section) = _loadConfig(args['config'] as String?);
  final configDir = configFile.parent.path;
  final keyPartsOut = section['key_parts_out'] as String?;
  if (keyPartsOut == null) {
    _fail(
      '`key_parts_out` is not set in ${configFile.path} — nothing to '
      'generate.\n'
      '\n'
      'If the key ships inside the app (EmbeddedKeyProvider), add it there:\n'
      '\n'
      '  litert_crypto:\n'
      '    key_parts_out: lib/model_master_key.dart\n'
      '\n'
      'If the key comes from a server, license, or secure storage instead, '
      'you do not\nneed `keyparts` at all.',
    );
  }
  await _writeKeyParts(
    _resolve(configDir, section['key_file'] as String? ?? _defaultKeyPath),
    _resolve(configDir, keyPartsOut),
    section['key_parts_symbol'] as String? ?? _defaultKeyPartsSymbol,
  );
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
      _findPubspecConfigOrNull(Directory.current) ??
      _fail(
        'No config found: no $_configFileName and no `litert_crypto:` '
        'section in a pubspec.yaml — searched here and every parent '
        'directory.\n\n'
        'Create a config with:  dart run litert_crypto init\n'
        '(or add a top-level `litert_crypto:` section to your pubspec.yaml)',
      );
}

/// Parses [configFile] and returns its `litert_crypto:` section.
YamlMap _readConfigSection(File configFile) {
  final doc = loadYaml(configFile.readAsStringSync());
  final section = doc is YamlMap ? doc['litert_crypto'] : null;
  if (section is! YamlMap) {
    _fail('${configFile.path} must contain a top-level `litert_crypto:` section.');
  }
  return section;
}

/// Locates the config (see [_findConfig]) and parses it in one step.
(File, YamlMap) _loadConfig(String? explicitPath) {
  final configFile = _findConfig(explicitPath);
  return (configFile, _readConfigSection(configFile));
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

/// Nearest pubspec.yaml at or above [start] with a top-level `litert_crypto:`
/// section — the file-less setup: in transformer mode the whole config is two
/// lines, which sit well next to the asset registration they belong to.
///
/// Callers try [_findConfigOrNull] first, so a dedicated litert_crypto.yaml
/// anywhere on the walk wins over any pubspec section and existing setups are
/// untouched. Pubspecs without the section (and unparseable ones) are walked
/// past, which lets a package in a monorepo inherit a parent's section.
File? _findPubspecConfigOrNull(Directory start) {
  var dir = start;
  while (true) {
    final candidate = File('${dir.path}/pubspec.yaml');
    if (candidate.existsSync()) {
      Object? doc;
      try {
        doc = loadYaml(candidate.readAsStringSync());
      } on Exception {
        doc = null;
      }
      if (doc is YamlMap && doc['litert_crypto'] is YamlMap) return candidate;
    }
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
        ..writeln('$outPath now takes precedence for commands run from its')
        ..writeln('directory or below, because encrypt uses the nearest one.')
        ..writeln('Delete the new file if you meant to use the existing')
        ..writeln('config instead.')
        ..writeln('');
    }

    // Same shadowing risk for a pubspec-section config: the dedicated file
    // always wins over it.
    final pubspecConfig = _findPubspecConfigOrNull(file.absolute.parent);
    if (pubspecConfig != null) {
      stdout
        ..writeln('Note: ${pubspecConfig.path} carries a `litert_crypto:`')
        ..writeln('section. $outPath now takes precedence — a dedicated')
        ..writeln('config file always wins over the pubspec section. Delete')
        ..writeln('the new file if you meant to keep using the section.')
        ..writeln('');
    }
  }

  file.parent.createSync(recursive: true);
  file.writeAsStringSync('''
# litert_crypto — model encryption config.
# Paths are relative to this file.
litert_crypto:
  # Written by `dart run litert_crypto keygen`. Never commit it.
  key_file: $_defaultKeyPath

  # Optional: generated Dart source rebuilding the key from XOR parts, for
  # EmbeddedKeyProvider. Remove this line if the key does not ship with the app
  # (license file, server, secure storage) — see the README on where keys live.
  # Generate with: dart run litert_crypto keyparts
  key_parts_out: lib/model_master_key.dart

  # Transformer mode needs nothing below: register the plaintext model as an
  # asset with `transformers: [package: litert_crypto]` in pubspec.yaml and
  # `flutter build` encrypts it on the way into the bundle. The `models` list
  # is for encrypting outside the build (`dart run litert_crypto encrypt`) —
  # e.g. models your app downloads from a server.
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
    ..writeln('  3. either register your models as assets with the litert_crypto')
    ..writeln('     transformer (flutter build encrypts them — see the README),')
    ..writeln('     or list them under `models:` and run `dart run litert_crypto encrypt`')
    ..writeln('  4. dart run litert_crypto keyparts   (only if the key ships in the app)');
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

  if (outFile.existsSync()) {
    final content = outFile.readAsStringSync();
    // Up to date only if generated from this key AND declaring the current
    // symbol — the file depends on both inputs, so a renamed
    // `key_parts_symbol` must regenerate just like a changed key.
    if (content.contains('$_fingerprintMarker$fingerprint') &&
        content.contains('KeyProvider $symbol()')) {
      stdout.writeln('Key parts already match $keyPath: $outPath');
      return;
    }
  }

  final random = Random.secure();
  final partA = List<int>.generate(key.length, (_) => random.nextInt(256));
  final partB = List<int>.generate(key.length, (i) => key[i] ^ partA[i]);

  outFile.parent.createSync(recursive: true);
  outFile.writeAsStringSync('''
// GENERATED by the litert_crypto CLI (`keyparts` / `encrypt`) — do not edit by hand.
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
      'Key file not found: $keyPath\n'
      'Run `dart run litert_crypto keygen` first. On CI (where the key file '
      'is not checked out), provision it from a secret before the build.',
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
