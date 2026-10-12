/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  GPT-6 Astra <noreply@openai.com>
*/

import 'dart:typed_data';

/// Format and architectures advertised by a native library, or null for an
/// unsupported or truncated header. This is a packaging check, not a loader.
/// Universal Mach-O libraries are accepted when they contain the target slice.
(String, Set<String>)? binaryTargets(Uint8List bytes) {
  final data = ByteData.sublistView(bytes);
  final length = data.lengthInBytes;
  if (length < 8) return null;
  int u16(int at, Endian endian) => data.getUint16(at, endian);
  int u32(int at, Endian endian) => data.getUint32(at, endian);
  final magic = u32(0, Endian.big);
  if (magic == 0x7f454c46) {
    final bits = bytes[4];
    final encoding = bytes[5];
    if ((bits != 1 && bits != 2) ||
        (encoding != 1 && encoding != 2) ||
        length < (bits == 1 ? 52 : 64)) {
      return null;
    }
    final endian = encoding == 1 ? Endian.little : Endian.big;
    final arch = switch ((u16(18, endian), bits)) {
      (0x3e, 2) => 'x64',
      (0xb7, 2) => 'arm64',
      (0x03, 1) => 'ia32',
      (0x28, 1) => 'arm',
      (0xf3, 2) => 'riscv64',
      (0xf3, 1) => 'riscv32',
      _ => 'unknown',
    };
    // Dart's supported architectures are little-endian. A big-endian ELF
    // must not be accepted just because its e_machine has the same value.
    return ('ELF', {encoding == 1 ? arch : '$arch (big-endian)'});
  }
  if (magic == 0xfeedface ||
      magic == 0xfeedfacf ||
      magic == 0xcefaedfe ||
      magic == 0xcffaedfe) {
    final endian = magic == 0xfeedface || magic == 0xfeedfacf
        ? Endian.big
        : Endian.little;
    final wide = magic == 0xfeedfacf || magic == 0xcffaedfe;
    if (length < (wide ? 32 : 28)) return null;
    final cpu = u32(4, endian);
    if ((cpu & 0x01000000 != 0) != wide) return null;
    return ('Mach-O', {_machArch(cpu)});
  }
  if (magic == 0xcafebabe ||
      magic == 0xbebafeca ||
      magic == 0xcafebabf ||
      magic == 0xbfbafeca) {
    final endian = magic == 0xcafebabe || magic == 0xcafebabf
        ? Endian.big
        : Endian.little;
    final wide = magic == 0xcafebabf || magic == 0xbfbafeca;
    final count = u32(4, endian);
    final stride = wide ? 32 : 20;
    if (count == 0 || count > (length - 8) ~/ stride) return null;
    final arches = <String>{};
    for (var i = 0; i < count; i++) {
      final at = 8 + i * stride;
      final cpu = u32(at, endian);
      final offset = wide
          ? data.getUint64(at + 8, endian)
          : u32(at + 8, endian);
      final size = wide
          ? data.getUint64(at + 16, endian)
          : u32(at + 12, endian);
      if (offset < 8 + count * stride ||
          size < 28 ||
          offset > length ||
          size > length - offset) {
        return null;
      }
      // Require a thin slice (no recursion through an untrusted fat header).
      final sliceMagic = u32(offset, Endian.big);
      if (sliceMagic != 0xfeedface &&
          sliceMagic != 0xfeedfacf &&
          sliceMagic != 0xcefaedfe &&
          sliceMagic != 0xcffaedfe) {
        return null;
      }
      final slice = binaryTargets(
        Uint8List.sublistView(bytes, offset, offset + size),
      );
      if (slice == null || !slice.$2.contains(_machArch(cpu))) return null;
      arches.addAll(slice.$2);
    }
    return ('Mach-O', arches);
  }
  if (bytes[0] == 0x4d && bytes[1] == 0x5a && length >= 0x40) {
    final pe = u32(0x3c, Endian.little);
    if (pe < 0x40 || pe > length - 24 || u32(pe, Endian.little) != 0x4550) {
      return null;
    }
    final arch = switch (u16(pe + 4, Endian.little)) {
      0x8664 => 'x64',
      0xaa64 => 'arm64',
      0x014c => 'ia32',
      0x01c4 => 'arm',
      _ => 'unknown',
    };
    return ('PE', {arch});
  }
  return null;
}

String _machArch(int cpu) => switch (cpu) {
  0x01000007 => 'x64',
  0x0100000c => 'arm64',
  7 => 'ia32',
  12 => 'arm',
  _ => 'unknown',
};
