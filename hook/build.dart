/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// Provides the native shim (native/sbq) as the code asset `package:switchboard_quic/sbq`,
// which the @Native bindings in lib/src/native/sbq_bindings.g.dart resolve against.
//
// 1. A prebuilt library at native/sbq/prebuilt/<os>_<arch>/<file> (libsbq.so, libsbq.dylib,
//    sbq.dll) is used as it is. Release builds of the package ship these.
// 2. Otherwise, for the host's own OS and architecture, `cargo build --release` builds the crate
//    (cargo from PATH, or rustup's default ~/.cargo/bin), into native/sbq/target.
// 3. Otherwise the build fails, naming both ways out.
//
// Which of the two happened is printed (`dart run -v`, or the hook's stdout file under
// .dart_tool/hooks_runner) and written to sbq_source.txt in the hook's output directory.

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;
    final code = input.config.code;
    final os = code.targetOS;
    final arch = code.targetArchitecture;
    final fileName = os.dylibFileName('sbq');
    final crate = input.packageRoot.resolve('native/sbq/');
    final prebuilt = crate.resolve(
      'prebuilt/${os.name}_${arch.name}/$fileName',
    );

    final Uri library;
    final String source;
    if (File.fromUri(prebuilt).existsSync()) {
      library = prebuilt;
      source = 'prebuilt ${prebuilt.toFilePath()}';
      output.dependencies.add(prebuilt);
    } else {
      final cargo = _findCargo();
      if (os != OS.current || arch != Architecture.current || cargo == null) {
        throw UnsupportedError(
          'switchboard_quic: no prebuilt native library for ${os.name}_${arch.name} '
          '(expected ${prebuilt.toFilePath()})'
          '${cargo == null ? ', and cargo was not found on PATH or in ~/.cargo/bin' : ', and cargo builds for the host (${OS.current.name}_${Architecture.current.name}) only'}. '
          'Install Rust (https://rustup.rs) to build it from native/sbq, or place a prebuilt '
          'library at that path (see native/README.md).',
        );
      }
      final target = crate.resolve('target/');
      final result = await Process.run(
        cargo,
        [
          'build',
          '--release',
          '--manifest-path',
          crate.resolve('Cargo.toml').toFilePath(),
        ],
        environment: {'CARGO_TARGET_DIR': target.toFilePath()},
      );
      if (result.exitCode != 0) {
        throw StateError(
          'switchboard_quic: cargo build of native/sbq failed '
          '(exit ${result.exitCode}):\n${result.stderr}',
        );
      }
      library = target.resolve('release/$fileName');
      source = 'cargo build ($cargo) -> ${library.toFilePath()}';
      output.dependencies
        ..add(crate.resolve('Cargo.toml'))
        ..add(crate.resolve('Cargo.lock'));
      for (final f in Directory.fromUri(
        crate.resolve('src/'),
      ).listSync(recursive: true)) {
        if (f is File) output.dependencies.add(f.uri);
      }
    }
    stdout.writeln('switchboard_quic: native library from $source');
    await File.fromUri(input.outputDirectory.resolve('sbq_source.txt'))
        .writeAsString('$source\n');
    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: 'sbq',
        linkMode: DynamicLoadingBundled(),
        file: library,
      ),
    );
  });
}

/// cargo on PATH, else rustup's default location.
String? _findCargo() {
  final exe = Platform.isWindows ? 'cargo.exe' : 'cargo';
  final path = Platform.environment['PATH'] ?? '';
  for (final dir in path.split(Platform.isWindows ? ';' : ':')) {
    if (dir.isEmpty) continue;
    final f = File('$dir${Platform.pathSeparator}$exe');
    if (f.existsSync()) return f.path;
  }
  final home =
      Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'];
  if (home != null) {
    final f = File(
      '$home${Platform.pathSeparator}.cargo${Platform.pathSeparator}bin${Platform.pathSeparator}$exe',
    );
    if (f.existsSync()) return f.path;
  }
  return null;
}
