/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  GPT-6 Astra <noreply@openai.com>
*/

@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:test/test.dart';

import '../hook/binary_target.dart';

Uint8List elf(int machine, int bits, Endian endian) {
  final bytes = Uint8List(
    64,
  )..setAll(0, [0x7f, 0x45, 0x4c, 0x46, bits, endian == Endian.little ? 1 : 2]);
  ByteData.sublistView(bytes).setUint16(18, machine, endian);
  return bytes;
}

Uint8List mach(int cpu, Endian endian) {
  final wide = cpu & 0x01000000 != 0;
  final bytes = Uint8List(wide ? 32 : 28);
  ByteData.sublistView(bytes)
    ..setUint32(0, wide ? 0xfeedfacf : 0xfeedface, endian)
    ..setUint32(4, cpu, endian);
  return bytes;
}

Uint8List fat(List<int> cpus, Endian endian, bool wide) {
  final stride = wide ? 32 : 20;
  final bytes = Uint8List(8 + stride * cpus.length + 32 * cpus.length);
  final data = ByteData.sublistView(bytes)
    ..setUint32(0, wide ? 0xcafebabf : 0xcafebabe, endian)
    ..setUint32(4, cpus.length, endian);
  for (var i = 0; i < cpus.length; i++) {
    final at = 8 + stride * i;
    final offset = 8 + stride * cpus.length + 32 * i;
    data.setUint32(at, cpus[i], endian);
    if (wide) {
      data.setUint64(at + 8, offset, endian);
      data.setUint64(at + 16, 32, endian);
    } else {
      data.setUint32(at + 8, offset, endian);
      data.setUint32(at + 12, 32, endian);
    }
    bytes.setAll(offset, mach(cpus[i], Endian.little));
  }
  return bytes;
}

List<Object>? target(Uint8List bytes) {
  final found = binaryTargets(bytes);
  return found == null ? null : [found.$1, found.$2];
}

void main() {
  test('ELF class, machine and byte order are all checked', () {
    for (final (machine, bits, arch) in [
      (0x3e, 2, 'x64'),
      (0xb7, 2, 'arm64'),
      (3, 1, 'ia32'),
      (0x28, 1, 'arm'),
      (0xf3, 1, 'riscv32'),
      (0xf3, 2, 'riscv64'),
    ]) {
      expect(target(elf(machine, bits, Endian.little)), [
        'ELF',
        {arch},
      ]);
      expect(target(elf(machine, bits, Endian.big)), [
        'ELF',
        {'$arch (big-endian)'},
      ]);
    }
    expect(target(elf(0x3e, 1, Endian.little)), [
      'ELF',
      {'unknown'},
    ]);
  });

  test('all four thin Mach-O magic variants', () {
    for (final endian in [Endian.little, Endian.big]) {
      for (final (cpu, arch) in [
        (7, 'ia32'),
        (12, 'arm'),
        (0x01000007, 'x64'),
        (0x0100000c, 'arm64'),
      ]) {
        expect(target(mach(cpu, endian)), [
          'Mach-O',
          {arch},
        ]);
      }
    }
  });

  test('fat Mach-O reports the actual slices in both fat table formats', () {
    for (final endian in [Endian.little, Endian.big]) {
      for (final wide in [false, true]) {
        expect(target(fat([0x01000007, 0x0100000c], endian, wide)), [
          'Mach-O',
          {'x64', 'arm64'},
        ]);
        expect(target(fat([0x0100000c], endian, wide)), [
          'Mach-O',
          {'arm64'},
        ]);
      }
    }
  });

  test('fat Mach-O cannot advertise an absent or mislabeled slice', () {
    final bytes = fat([0x01000007], Endian.big, false);
    ByteData.sublistView(bytes).setUint32(8, 0x0100000c, Endian.big);
    expect(target(bytes), isNull);
    expect(target(Uint8List.sublistView(bytes, 0, 40)), isNull);
  });

  test('PE follows e_lfanew even beyond the first page', () {
    for (final (machine, arch) in [
      (0x8664, 'x64'),
      (0xaa64, 'arm64'),
      (0x014c, 'ia32'),
      (0x01c4, 'arm'),
    ]) {
      final bytes = Uint8List(0x2020)..setAll(0, [0x4d, 0x5a]);
      ByteData.sublistView(bytes)
        ..setUint32(0x3c, 0x2000, Endian.little)
        ..setUint32(0x2000, 0x4550, Endian.little)
        ..setUint16(0x2004, machine, Endian.little);
      expect(target(bytes), [
        'PE',
        {arch},
      ]);
      expect(target(Uint8List.sublistView(bytes, 0, 0x2004)), isNull);
    }
  });

  test('unknown and truncated headers fail closed without throwing', () {
    expect(target(Uint8List.fromList('not a library'.codeUnits)), isNull);
    for (final bytes in [
      elf(0x3e, 2, Endian.little),
      mach(0x0100000c, Endian.little),
      fat([0x01000007], Endian.big, true),
    ]) {
      for (var n = 0; n < bytes.length; n++) {
        expect(target(Uint8List.sublistView(bytes, 0, n)), isNull);
      }
    }
  });
}
