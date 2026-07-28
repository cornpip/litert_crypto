import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:litert_crypto/codec.dart';
import 'package:yaml/yaml.dart';

const _defaultKeyPath = '.secrets/model.key';
const _configFileName = 'litert_crypto.yaml';

Future<void> main(List<String> arguments) async {
  final parser = ArgParser()
    ..addCommand(
      'keygen',
      ArgParser()..addOption('out', help: 'Key file path', defaultsTo: _defaultKeyPath),
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
                '(defaults to the source file name)'),
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
    case 'keygen':
      await _keygen(command);
    case 'encrypt':
      await _encrypt(command);
  }
}

String _usage(ArgParser parser) => '''
litert_crypto — encrypt LiteRT (tflite) models

Usage:
  dart run litert_crypto keygen [--out $_defaultKeyPath]
  dart run litert_crypto encrypt --key <keyfile> --in <model.tflite> --out <model.tflite.enc> [--key-id 0] [--label name]
  dart run litert_crypto encrypt          (uses $_configFileName)

Config file ($_configFileName):
  litert_crypto:
    key_file: $_defaultKeyPath
    models:
      - src: models_src/model.tflite
        out: assets/tflite_model/model.tflite.enc
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
  stdout.writeln('Wrote ${LrtcCodec.keyLength}-byte key: $outPath');
  stdout.writeln('Keep it out of version control (add to .gitignore).');
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
    final keyId = int.tryParse(args['key-id'] as String) ?? 0;
    await _encryptOne(keyPath, input, output, keyId, args['label'] as String?);
    return;
  }

  // Config file mode.
  final configFile = File(_configFileName);
  if (!configFile.existsSync()) {
    _fail('No arguments and no $_configFileName found.\n\n'
        'Create one:\n'
        'litert_crypto:\n'
        '  key_file: $_defaultKeyPath\n'
        '  models:\n'
        '    - src: models_src/model.tflite\n'
        '      out: assets/tflite_model/model.tflite.enc');
  }
  final doc = loadYaml(configFile.readAsStringSync());
  final section = doc is YamlMap ? doc['litert_crypto'] : null;
  if (section is! YamlMap) {
    _fail('$_configFileName must contain a top-level `litert_crypto:` section.');
  }
  final keyPath = section['key_file'] as String? ?? _defaultKeyPath;
  final models = section['models'];
  if (models is! YamlList || models.isEmpty) {
    _fail('`litert_crypto.models` must be a non-empty list of {src, out}.');
  }
  for (final entry in models) {
    if (entry is! YamlMap || entry['src'] == null || entry['out'] == null) {
      _fail('Each model entry needs `src` and `out`.');
    }
    final keyId = int.tryParse('${entry['key_id'] ?? 0}') ?? 0;
    await _encryptOne(
      keyPath,
      entry['src'] as String,
      entry['out'] as String,
      keyId,
      entry['label'] as String?,
    );
  }
}

Future<void> _encryptOne(
  String keyPath,
  String inputPath,
  String outputPath,
  int keyId,
  String? label,
) async {
  final keyFile = File(keyPath);
  if (!keyFile.existsSync()) {
    _fail('Key file not found: $keyPath (run `dart run litert_crypto keygen` first).');
  }
  final key = Uint8List.fromList(base64Decode(keyFile.readAsStringSync().trim()));

  final inputFile = File(inputPath);
  if (!inputFile.existsSync()) {
    _fail('Input model not found: $inputPath');
  }
  final plain = inputFile.readAsBytesSync();

  final effectiveLabel = label ?? inputPath.split(RegExp(r'[/\\]')).last;
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
