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
//    sbq.dll) is used as it is. The package's releases carry these (tool/fetch_prebuilt.sh
//    downloads them there); the hook itself never downloads anything.
// 2. Otherwise, for the host's own OS and architecture, `cargo build --release` builds the crate
//    (cargo from PATH, else $CARGO_HOME/bin, else rustup's default ~/.cargo/bin or
//    %USERPROFILE%\.cargo\bin), into native/sbq/target. When rustc's own host is of another
//    architecture than the Dart VM (an x64 Dart SDK under Rosetta 2 or Windows' emulation with
//    an arm64 Rust toolchain), it builds with an explicit `--target` of the VM's architecture.
// 3. Otherwise the build fails, naming the ways out. iOS and Android are never built here.
//
// A library whose header (ELF, Mach-O or PE) names another architecture or format than the
// target's fails the build too.
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
      final missing =
          'switchboard_quic: no prebuilt native library for '
          '${os.name}_${arch.name} (expected ${prebuilt.toFilePath()})';
      const fetch =
          'tool/fetch_prebuilt.sh downloads the libraries of a release there; '
          'see native/README.md';
      if (os == OS.iOS || os == OS.android) {
        throw UnsupportedError(
          '$missing. The hook builds the library for the host it runs on only, '
          'and releases carry Linux, macOS and Windows libraries only: build '
          'native/sbq for this target with its SDK and place the library at '
          'that path (native/README.md, "Platforms").',
        );
      }
      if (os != OS.current || arch != Architecture.current) {
        throw UnsupportedError(
          '$missing, and cargo builds for the host '
          '(${OS.current.name}_${Architecture.current.name}) only. Place a '
          'prebuilt library at that path ($fetch).',
        );
      }
      final cargo = _findCargo();
      if (cargo == null) {
        throw UnsupportedError(
          '$missing, and cargo was not found on PATH, in \$CARGO_HOME/bin or '
          'in ~/.cargo/bin. Install Rust (https://rustup.rs) to build it from '
          'native/sbq, or place a prebuilt library at that path ($fetch).',
        );
      }
      final triple = await _cargoTarget(cargo, arch);
      final target = crate.resolve('target/');
      final result = await Process.run(
        cargo,
        [
          'build',
          '--release',
          '--manifest-path',
          crate.resolve('Cargo.toml').toFilePath(),
          if (triple != null) ...['--target', triple],
        ],
        environment: {'CARGO_TARGET_DIR': target.toFilePath()},
      );
      if (result.exitCode != 0) {
        throw StateError(
          'switchboard_quic: cargo build of native/sbq failed '
          '(exit ${result.exitCode}):\n${result.stderr}',
        );
      }
      library = target.resolve(
        '${triple == null ? '' : '$triple/'}release/$fileName',
      );
      source =
          'cargo build ($cargo${triple == null ? '' : ' --target $triple'}) '
          '-> ${library.toFilePath()}';
      output.dependencies
        ..add(crate.resolve('Cargo.toml'))
        ..add(crate.resolve('Cargo.lock'));
      for (final f in Directory.fromUri(
        crate.resolve('src/'),
      ).listSync(recursive: true)) {
        if (f is File) output.dependencies.add(f.uri);
      }
    }
    // Dart 3.13's hooks runner bundles a library of another architecture
    // without a word, which then fails to load with a misleading message.
    final found = _binaryTarget(File.fromUri(library));
    if (found != null && found != (_binaryFormat(os), arch.name)) {
      throw StateError(
        'switchboard_quic: ${library.toFilePath()} is built for ${found.$2} '
        '(${found.$1}), not for ${os.name}_${arch.name}',
      );
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

/// The binary format of [os]'s libraries.
String _binaryFormat(OS os) => switch (os) {
  OS.windows => 'PE',
  OS.macOS || OS.iOS => 'Mach-O',
  _ => 'ELF',
};

/// The format and the architecture (an [Architecture] name) of the library
/// [file] from its header, or null for a format or a machine not known here
/// (a universal Mach-O binary among them).
(String, String)? _binaryTarget(File file) {
  final List<int> head;
  try {
    final f = file.openSync();
    try {
      head = f.readSync(4096);
    } finally {
      f.closeSync();
    }
  } on FileSystemException {
    return null;
  }
  int u16(int at) => head[at] | head[at + 1] << 8;
  int u32(int at) => u16(at) | u16(at + 2) << 16;
  if (head.length >= 20 &&
      head[0] == 0x7f &&
      head[1] == 0x45 &&
      head[2] == 0x4c &&
      head[3] == 0x46 &&
      head[5] == 1) {
    final arch = switch (u16(18)) {
      0x3e => 'x64',
      0xb7 => 'arm64',
      0x03 => 'ia32',
      0x28 => 'arm',
      0xf3 => head[4] == 2 ? 'riscv64' : 'riscv32',
      _ => null,
    };
    return arch == null ? null : ('ELF', arch);
  }
  if (head.length >= 8 && u32(0) == 0xfeedfacf) {
    final arch = switch (u32(4)) {
      0x01000007 => 'x64',
      0x0100000c => 'arm64',
      _ => null,
    };
    return arch == null ? null : ('Mach-O', arch);
  }
  if (head.length >= 0x40 && head[0] == 0x4d && head[1] == 0x5a) {
    final pe = u32(0x3c);
    if (pe + 6 > head.length || u32(pe) != 0x00004550) return null;
    final arch = switch (u16(pe + 4)) {
      0x8664 => 'x64',
      0xaa64 => 'arm64',
      0x014c => 'ia32',
      _ => null,
    };
    return arch == null ? null : ('PE', arch);
  }
  return null;
}

/// cargo on PATH, else in `$CARGO_HOME/bin`, else in rustup's default location
/// (`~/.cargo/bin`, `%USERPROFILE%\.cargo\bin` on Windows).
String? _findCargo() {
  final env = Platform.environment;
  final sep = Platform.pathSeparator;
  final exe = Platform.isWindows ? 'cargo.exe' : 'cargo';
  final dirs = [
    ...?env['PATH']?.split(Platform.isWindows ? ';' : ':'),
    if (env['CARGO_HOME'] case final home?) '$home${sep}bin',
    for (final home in [env['HOME'], env['USERPROFILE']])
      if (home != null) '$home$sep.cargo${sep}bin',
  ];
  for (var dir in dirs) {
    // A Windows PATH entry may be quoted.
    if (dir.length >= 2 && dir.startsWith('"') && dir.endsWith('"')) {
      dir = dir.substring(1, dir.length - 1);
    }
    if (dir.isEmpty) continue;
    final f = File('$dir$sep$exe');
    if (f.existsSync()) return f.path;
  }
  return null;
}

/// The `--target` that builds for [arch] on this host: null when rustc's own
/// host triple is of that architecture (the usual case: cargo's default), else
/// that triple with its architecture replaced, so that an x64 Dart VM under
/// Rosetta 2 or Windows' emulation gets an x64 library from an arm64 Rust
/// toolchain (which then needs that target: `rustup target add`). Null too when
/// rustc cannot tell or the architecture is not one this maps; the hook checks
/// the library's architecture either way.
Future<String?> _cargoTarget(String cargo, Architecture arch) async {
  final rustArch = switch (arch) {
    Architecture.x64 => 'x86_64',
    Architecture.arm64 => 'aarch64',
    _ => null,
  };
  if (rustArch == null) return null;
  final sep = Platform.pathSeparator;
  final sibling = File(
    '${File(cargo).parent.path}$sep${Platform.isWindows ? 'rustc.exe' : 'rustc'}',
  );
  final ProcessResult result;
  try {
    result = await Process.run(sibling.existsSync() ? sibling.path : 'rustc', [
      '-vV',
    ]);
  } on ProcessException {
    return null;
  }
  if (result.exitCode != 0) return null;
  for (final line in (result.stdout as String).split('\n')) {
    if (!line.startsWith('host: ')) continue;
    final host = line.substring('host: '.length).trim();
    final hostArch = host.split('-').first;
    return hostArch == rustArch
        ? null
        : '$rustArch${host.substring(hostArch.length)}';
  }
  return null;
}
