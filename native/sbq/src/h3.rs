/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

//! The HTTP/3 codecs the WebTransport layer needs (RFC 9114, RFC 9204), and nothing more: QUIC
//! variable-length integers, frames, SETTINGS, and a QPACK that never uses the dynamic table. The
//! encoder writes static table references and literals (never Huffman, which a sender may skip);
//! the decoder reads static references and literals, Huffman-coded or not (RFC 7541 Appendix B),
//! and refuses any reference to the dynamic table, which this side announces with a capacity of
//! 0 (QPACK_MAX_TABLE_CAPACITY 0, QPACK_BLOCKED_STREAMS 0). Everything here is a pure function of
//! its input; the stream handling is in `h3conn`.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::h3_tables::{HUFFMAN, STATIC_TABLE};

/// HTTP/3 error codes (RFC 9114 section 8.1, RFC 9204 section 6), the whole registry of them.
#[allow(dead_code)]
pub mod err {
    pub(crate) const H3_NO_ERROR: u64 = 0x100;
    pub(crate) const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x101;
    pub(crate) const H3_INTERNAL_ERROR: u64 = 0x102;
    pub(crate) const H3_STREAM_CREATION_ERROR: u64 = 0x103;
    pub(crate) const H3_CLOSED_CRITICAL_STREAM: u64 = 0x104;
    pub(crate) const H3_FRAME_UNEXPECTED: u64 = 0x105;
    pub(crate) const H3_FRAME_ERROR: u64 = 0x106;
    pub(crate) const H3_EXCESSIVE_LOAD: u64 = 0x107;
    pub(crate) const H3_ID_ERROR: u64 = 0x108;
    pub(crate) const H3_SETTINGS_ERROR: u64 = 0x109;
    pub(crate) const H3_MISSING_SETTINGS: u64 = 0x10a;
    pub(crate) const H3_REQUEST_REJECTED: u64 = 0x10b;
    pub(crate) const H3_REQUEST_CANCELLED: u64 = 0x10c;
    pub(crate) const H3_REQUEST_INCOMPLETE: u64 = 0x10d;
    pub(crate) const H3_MESSAGE_ERROR: u64 = 0x10e;
    pub(crate) const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;
    pub(crate) const QPACK_ENCODER_STREAM_ERROR: u64 = 0x201;
    pub(crate) const QPACK_DECODER_STREAM_ERROR: u64 = 0x202;
}

/// Frame types (RFC 9114 section 7.2), and WebTransport's bidirectional stream signal.
pub mod frame {
    pub(crate) const DATA: u64 = 0x00;
    pub(crate) const HEADERS: u64 = 0x01;
    pub(crate) const CANCEL_PUSH: u64 = 0x03;
    pub(crate) const SETTINGS: u64 = 0x04;
    pub(crate) const PUSH_PROMISE: u64 = 0x05;
    pub(crate) const GOAWAY: u64 = 0x07;
    pub(crate) const MAX_PUSH_ID: u64 = 0x0d;
    /// WT_STREAM: not a frame, the signal at the start of a WebTransport bidirectional stream.
    pub(crate) const WT_STREAM: u64 = 0x41;

    /// HTTP/2 frame types HTTP/3 reserves (PRIORITY, PING, WINDOW_UPDATE, CONTINUATION):
    /// receiving one is H3_FRAME_UNEXPECTED.
    pub fn is_reserved_h2(t: u64) -> bool {
        matches!(t, 0x02 | 0x06 | 0x08 | 0x09)
    }
}

/// Unidirectional stream types (RFC 9114 section 6.2, RFC 9204, the WebTransport draft).
pub mod stream_type {
    pub(crate) const CONTROL: u64 = 0x00;
    pub(crate) const PUSH: u64 = 0x01;
    pub(crate) const QPACK_ENCODER: u64 = 0x02;
    pub(crate) const QPACK_DECODER: u64 = 0x03;
    pub(crate) const WEBTRANSPORT: u64 = 0x54;
}

/// SETTINGS identifiers.
pub mod setting {
    pub(crate) const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    pub(crate) const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    pub(crate) const QPACK_BLOCKED_STREAMS: u64 = 0x07;
    /// RFC 9220.
    pub(crate) const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
    /// RFC 9297.
    pub(crate) const H3_DATAGRAM: u64 = 0x33;
    /// The draft identifier of H3_DATAGRAM, still sent by Chrome.
    pub(crate) const H3_DATAGRAM_DRAFT: u64 = 0xffd277;
    /// draft-ietf-webtrans-http3-02 SETTINGS_ENABLE_WEBTRANSPORT (Chrome 149 sends it).
    pub(crate) const ENABLE_WEBTRANSPORT_DRAFT02: u64 = 0x2b603742;
    /// draft-ietf-webtrans-http3-07 to -12 SETTINGS_WEBTRANSPORT_MAX_SESSIONS.
    pub(crate) const WEBTRANSPORT_MAX_SESSIONS_DRAFT07: u64 = 0xc671706a;

    /// HTTP/2 settings HTTP/3 reserves: receiving one is H3_SETTINGS_ERROR.
    pub fn is_reserved_h2(id: u64) -> bool {
        matches!(id, 0x00 | 0x02 | 0x03 | 0x04 | 0x05)
    }
}

/// Whether `v` is a reserved ("GREASE") codepoint of the form 0x1f * N + 0x21 (frame and stream
/// types, settings, error codes).
pub fn is_grease(v: u64) -> bool {
    v >= 0x21 && (v - 0x21) % 0x1f == 0
}

// ---------------------------------------------------------------------------------------------
// QUIC variable-length integers (RFC 9000 section 16).

/// The largest value a variable-length integer holds.
pub(crate) const VARINT_MAX: u64 = (1 << 62) - 1;

/// The encoded length of `v` (1, 2, 4 or 8).
pub fn varint_len(v: u64) -> usize {
    if v < 1 << 6 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

/// The encoded length of a variable-length integer from its first byte.
pub fn varint_len_of_first(b0: u8) -> usize {
    1 << (b0 >> 6)
}

/// Appends `v` (at most `VARINT_MAX`) in its shortest encoding.
pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    debug_assert!(v <= VARINT_MAX);
    match varint_len(v) {
        1 => out.push(v as u8),
        2 => out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// Decodes a variable-length integer at the start of `b`: the value and its length, or None
/// while `b` holds less than the whole integer.
pub fn get_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let n = varint_len_of_first(first);
    if b.len() < n {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for &x in &b[1..n] {
        v = (v << 8) | u64::from(x);
    }
    Some((v, n))
}

// ---------------------------------------------------------------------------------------------
// Frames and SETTINGS.

/// Appends a frame: type, length, payload.
pub fn put_frame(out: &mut Vec<u8>, frame_type: u64, payload: &[u8]) {
    put_varint(out, frame_type);
    put_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// A frame's payload, framed.
pub fn frame(frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 16);
    put_frame(&mut out, frame_type, payload);
    out
}

/// The payload of a SETTINGS frame with `pairs`, in order.
pub fn encode_settings(pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(id, v) in pairs {
        put_varint(&mut out, id);
        put_varint(&mut out, v);
    }
    out
}

/// The most settings a peer may send in its SETTINGS frame (reserved ones included).
pub(crate) const MAX_SETTINGS: usize = 256;

/// The settings a peer sent: its values by identifier (reserved GREASE settings dropped), and
/// the order they came in, for logs.
#[derive(Clone, Debug, Default)]
pub struct PeerSettings {
    pub values: HashMap<u64, u64>,
    pub order: Vec<(u64, u64)>,
}

impl PeerSettings {
    pub fn get(&self, id: u64) -> Option<u64> {
        self.values.get(&id).copied()
    }

    /// Whether the peer supports HTTP/3 datagrams (either identifier with the value 1).
    pub fn datagrams(&self) -> bool {
        self.get(setting::H3_DATAGRAM) == Some(1) || self.get(setting::H3_DATAGRAM_DRAFT) == Some(1)
    }

    /// Whether the peer signals draft-02 WebTransport.
    pub fn draft02(&self) -> bool {
        self.get(setting::ENABLE_WEBTRANSPORT_DRAFT02) == Some(1)
    }

    /// The sessions a draft-07 peer accepts (0 when it does not signal draft-07).
    pub fn draft07_sessions(&self) -> u64 {
        self.get(setting::WEBTRANSPORT_MAX_SESSIONS_DRAFT07)
            .unwrap_or(0)
    }

    /// Whether the peer supports WebTransport in a version this side speaks.
    pub fn webtransport(&self) -> bool {
        self.datagrams() && (self.draft02() || self.draft07_sessions() > 0)
    }
}

/// Parses the payload of a SETTINGS frame. Errors are HTTP/3 error codes: H3_FRAME_ERROR for a
/// truncated pair, H3_SETTINGS_ERROR for a duplicate, a reserved HTTP/2 identifier or a value
/// out of its range, H3_EXCESSIVE_LOAD for more than `MAX_SETTINGS` pairs.
pub fn parse_settings(mut b: &[u8]) -> Result<PeerSettings, u64> {
    let mut s = PeerSettings::default();
    let mut count = 0;
    let mut seen = HashSet::new();
    while !b.is_empty() {
        let (id, n) = get_varint(b).ok_or(err::H3_FRAME_ERROR)?;
        b = &b[n..];
        let (v, n) = get_varint(b).ok_or(err::H3_FRAME_ERROR)?;
        b = &b[n..];
        count += 1;
        if count > MAX_SETTINGS {
            return Err(err::H3_EXCESSIVE_LOAD);
        }
        if setting::is_reserved_h2(id) || !seen.insert(id) {
            return Err(err::H3_SETTINGS_ERROR);
        }
        if matches!(
            id,
            setting::ENABLE_CONNECT_PROTOCOL
                | setting::H3_DATAGRAM
                | setting::H3_DATAGRAM_DRAFT
                | setting::ENABLE_WEBTRANSPORT_DRAFT02
        ) && v > 1
        {
            return Err(err::H3_SETTINGS_ERROR);
        }
        if is_grease(id) {
            continue;
        }
        if s.values.insert(id, v).is_some() {
            return Err(err::H3_SETTINGS_ERROR);
        }
        s.order.push((id, v));
    }
    Ok(s)
}

// ---------------------------------------------------------------------------------------------
// QPACK prefixed integers (RFC 7541 section 5.1, RFC 9204 section 4.1.1).

/// Appends `v` as a prefixed integer whose first byte carries `flags` in its bits above the
/// `prefix` low bits.
pub fn put_qint(out: &mut Vec<u8>, flags: u8, prefix: u8, mut v: u64) {
    let max = (1u64 << prefix) - 1;
    if v < max {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | max as u8);
    v -= max;
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Decodes a prefixed integer at `b[*pos]` with a `prefix`-bit prefix and advances `pos`. None
/// for a truncated or oversized integer (beyond 2^62).
pub fn get_qint(b: &[u8], pos: &mut usize, prefix: u8) -> Option<u64> {
    let max = (1u64 << prefix) - 1;
    let first = u64::from(*b.get(*pos)?) & max;
    *pos += 1;
    if first < max {
        return Some(first);
    }
    let mut v = max;
    let mut shift = 0u32;
    loop {
        let x = *b.get(*pos)?;
        *pos += 1;
        v = v.checked_add(u64::from(x & 0x7f).checked_shl(shift)?)?;
        if v > VARINT_MAX || shift > 56 {
            return None;
        }
        if x & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
    }
}

// ---------------------------------------------------------------------------------------------
// Huffman decoding (RFC 7541 section 5.2 and Appendix B).

/// The decoding tree of the Huffman code: node `i` has children `tree[i][bit]`; a child below
/// `LEAF` is another node, at or above it the symbol `child - LEAF`.
const LEAF: u16 = 0x8000;

fn huffman_tree() -> &'static [[u16; 2]] {
    static TREE: OnceLock<Vec<[u16; 2]>> = OnceLock::new();
    TREE.get_or_init(|| {
        let mut tree: Vec<[u16; 2]> = vec![[0, 0]];
        for (sym, &(code, len)) in HUFFMAN.iter().enumerate() {
            let mut node = 0usize;
            for i in (0..len).rev() {
                let bit = ((code >> i) & 1) as usize;
                if i == 0 {
                    assert_eq!(tree[node][bit], 0, "the Huffman code is not prefix-free");
                    tree[node][bit] = LEAF + sym as u16;
                } else {
                    let next = tree[node][bit];
                    if next == 0 {
                        tree.push([0, 0]);
                        let id = (tree.len() - 1) as u16;
                        tree[node][bit] = id;
                        node = id as usize;
                    } else {
                        assert!(next < LEAF, "the Huffman code is not prefix-free");
                        node = next as usize;
                    }
                }
            }
        }
        tree
    })
}

/// Decodes a Huffman-coded string into `out`, failing for a code that is not one, the EOS
/// symbol, padding longer than 7 bits or not made of 1 bits, or an output over `max` bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum HuffmanError {
    Malformed,
    TooLarge,
}

pub fn huffman_decode(b: &[u8], out: &mut Vec<u8>, max: usize) -> Result<(), HuffmanError> {
    let tree = huffman_tree();
    let mut node = 0usize;
    // Bits read since the last complete symbol, and whether they were all 1.
    let mut pending = 0u32;
    let mut ones = true;
    for &byte in b {
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) as usize;
            pending += 1;
            ones &= bit == 1;
            let next = tree[node][bit];
            if next >= LEAF {
                let sym = next - LEAF;
                if sym == 256 {
                    return Err(HuffmanError::Malformed);
                }
                if out.len() >= max {
                    return Err(HuffmanError::TooLarge);
                }
                out.push(sym as u8);
                node = 0;
                pending = 0;
                ones = true;
            } else if next == 0 {
                return Err(HuffmanError::Malformed);
            } else {
                node = next as usize;
            }
        }
    }
    if pending > 7 || !ones {
        return Err(HuffmanError::Malformed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// QPACK field sections (RFC 9204 section 4.5), static table and literals only.

/// The QPACK static table entry `i`.
pub fn static_entry(i: u64) -> Option<(&'static str, &'static str)> {
    STATIC_TABLE.get(usize::try_from(i).ok()?).copied()
}

/// One field line: name and value bytes.
pub type Field = (Vec<u8>, Vec<u8>);

/// Encodes a field section: the prefix of a section that references nothing of the dynamic
/// table (Required Insert Count 0, Base 0), then each field as an indexed line where the static
/// table has it, a literal with a static name reference where it has the name, a literal with a
/// literal name otherwise. No Huffman coding.
pub fn encode_field_section(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00];
    for &(name, value) in fields {
        let mut name_ref = None;
        let mut exact = None;
        for (i, &(n, v)) in STATIC_TABLE.iter().enumerate() {
            if n.as_bytes() == name {
                if v.as_bytes() == value {
                    exact = Some(i);
                    break;
                }
                name_ref.get_or_insert(i);
            }
        }
        if let Some(i) = exact {
            // Indexed Field Line, static: 1 T=1 index(6).
            put_qint(&mut out, 0xc0, 6, i as u64);
        } else if let Some(i) = name_ref {
            // Literal Field Line with Name Reference: 01 N=0 T=1 index(4), then the value.
            put_qint(&mut out, 0x50, 4, i as u64);
            put_qint(&mut out, 0x00, 7, value.len() as u64);
            out.extend_from_slice(value);
        } else {
            // Literal Field Line with Literal Name: 001 N=0 H=0 length(3), the name, the value.
            put_qint(&mut out, 0x20, 3, name.len() as u64);
            out.extend_from_slice(name);
            put_qint(&mut out, 0x00, 7, value.len() as u64);
            out.extend_from_slice(value);
        }
    }
    out
}

/// Why a field section was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldError {
    /// Not decodable without the dynamic table, or malformed: a connection error of type
    /// QPACK_DECOMPRESSION_FAILED.
    Qpack,
    /// Over the size this side accepts (`max`, counted as RFC 9114 section 4.2.2 does: each
    /// field's name and value plus 32): a stream error.
    TooLarge,
}

/// Reads a string literal whose length has a `prefix`-bit prefix and whose H flag is the bit
/// just above it. `budget` is what is left of the section's size limit.
fn get_string(b: &[u8], pos: &mut usize, prefix: u8, budget: usize) -> Result<Vec<u8>, FieldError> {
    let huffman = b.get(*pos).ok_or(FieldError::Qpack)? & (1 << prefix) != 0;
    let len = get_qint(b, pos, prefix).ok_or(FieldError::Qpack)?;
    let len = usize::try_from(len).map_err(|_| FieldError::Qpack)?;
    let end = pos.checked_add(len).ok_or(FieldError::Qpack)?;
    let raw = b.get(*pos..end).ok_or(FieldError::Qpack)?;
    *pos = end;
    if huffman {
        let mut out = Vec::with_capacity(len.min(budget));
        match huffman_decode(raw, &mut out, budget) {
            Ok(()) => Ok(out),
            Err(HuffmanError::TooLarge) => Err(FieldError::TooLarge),
            Err(HuffmanError::Malformed) => Err(FieldError::Qpack),
        }
    } else if len > budget {
        Err(FieldError::TooLarge)
    } else {
        Ok(raw.to_vec())
    }
}

/// Decodes a field section that uses the static table and literals only. A Required Insert Count
/// other than 0, or any line referring to the dynamic table, is a QPACK error (this side's
/// table capacity is 0); so is a truncated or malformed line. The decoded size is bounded by
/// `max`.
pub fn decode_field_section(b: &[u8], max: usize) -> Result<Vec<Field>, FieldError> {
    let mut pos = 0usize;
    // Encoded Required Insert Count (8-bit prefix) and Delta Base (sign bit, 7-bit prefix). With
    // a table capacity of 0 the only valid encoded Required Insert Count is 0.
    let ric = get_qint(b, &mut pos, 8).ok_or(FieldError::Qpack)?;
    if ric != 0 {
        return Err(FieldError::Qpack);
    }
    // A negative Base is forbidden even when no dynamic reference follows (RFC 9204 4.5.1.2).
    if b.get(pos).ok_or(FieldError::Qpack)? & 0x80 != 0 {
        return Err(FieldError::Qpack);
    }
    get_qint(b, &mut pos, 7).ok_or(FieldError::Qpack)?;
    let mut fields = Vec::new();
    let mut size = 0usize;
    while pos < b.len() {
        let first = b[pos];
        let budget = max.saturating_sub(size);
        let (name, value) = if first & 0x80 != 0 {
            // Indexed Field Line: 1 T index(6). T=0 is the dynamic table.
            if first & 0x40 == 0 {
                return Err(FieldError::Qpack);
            }
            let i = get_qint(b, &mut pos, 6).ok_or(FieldError::Qpack)?;
            let (n, v) = static_entry(i).ok_or(FieldError::Qpack)?;
            (n.as_bytes().to_vec(), v.as_bytes().to_vec())
        } else if first & 0x40 != 0 {
            // Literal Field Line with Name Reference: 01 N T index(4), value.
            if first & 0x10 == 0 {
                return Err(FieldError::Qpack);
            }
            let i = get_qint(b, &mut pos, 4).ok_or(FieldError::Qpack)?;
            let (n, _) = static_entry(i).ok_or(FieldError::Qpack)?;
            let v = get_string(b, &mut pos, 7, budget)?;
            (n.as_bytes().to_vec(), v)
        } else if first & 0x20 != 0 {
            // Literal Field Line with Literal Name: 001 N H length(3), name, value.
            let n = get_string(b, &mut pos, 3, budget)?;
            let v = get_string(b, &mut pos, 7, budget.saturating_sub(n.len()))?;
            (n, v)
        } else {
            // 0001: Indexed Field Line with Post-Base Index; 0000: Literal Field Line with
            // Post-Base Name Reference. Both are the dynamic table.
            return Err(FieldError::Qpack);
        };
        size = size.saturating_add(name.len() + value.len() + 32);
        if size > max {
            return Err(FieldError::TooLarge);
        }
        fields.push((name, value));
    }
    Ok(fields)
}

// ---------------------------------------------------------------------------------------------
// The peer's QPACK encoder and decoder streams.

/// Checks the peer's encoder stream. With a table capacity of 0 the only instruction it may send
/// is Set Dynamic Table Capacity with the value 0 (the byte 0x20); anything else (an insertion, a
/// duplicate, a larger capacity) is QPACK_ENCODER_STREAM_ERROR.
pub fn check_encoder_stream(b: &[u8]) -> Result<(), u64> {
    if b.iter().all(|&x| x == 0x20) {
        Ok(())
    } else {
        Err(err::QPACK_ENCODER_STREAM_ERROR)
    }
}

/// Checks the peer's decoder stream, across reads: Stream Cancellation is fine; Section
/// Acknowledgment (this side never sends a section that needs one) and Insert Count Increment
/// (this side never inserts) are QPACK_DECODER_STREAM_ERROR.
#[derive(Default)]
pub struct DecoderStreamCheck {
    /// Continuation bytes of a Stream Cancellation integer read so far, when inside one.
    continuation: Option<(u64, u32)>,
}

impl DecoderStreamCheck {
    pub fn feed(&mut self, b: &[u8]) -> Result<(), u64> {
        for &x in b {
            match self.continuation {
                Some((v, shift)) => {
                    let next = v.checked_add(u64::from(x & 0x7f) << shift);
                    let Some(next) = next.filter(|v| *v <= VARINT_MAX) else {
                        return Err(err::QPACK_DECODER_STREAM_ERROR);
                    };
                    if x & 0x80 != 0 && shift >= 56 {
                        return Err(err::QPACK_DECODER_STREAM_ERROR);
                    }
                    self.continuation = if x & 0x80 != 0 {
                        Some((next, shift + 7))
                    } else {
                        None
                    };
                }
                None => {
                    if x & 0xc0 != 0x40 {
                        return Err(err::QPACK_DECODER_STREAM_ERROR);
                    }
                    if x & 0x3f == 0x3f {
                        self.continuation = Some((63, 0));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn varints() {
        // RFC 9000 Appendix A.1 examples.
        for (bytes, value) in [
            ("c2197c5eff14e88c", 151_288_809_941_952_652u64),
            ("9d7f3e7d", 494_878_333),
            ("7bbd", 15_293),
            ("25", 37),
            ("4025", 37),
        ] {
            let b = hex(bytes);
            assert_eq!(get_varint(&b), Some((value, b.len())));
        }
        for v in [0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, VARINT_MAX] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            assert_eq!(out.len(), varint_len(v));
            assert_eq!(get_varint(&out), Some((v, out.len())));
            // Every truncation is "incomplete", never a wrong value.
            for n in 0..out.len() {
                assert_eq!(get_varint(&out[..n]), None);
            }
        }
        // The stream signals of WebTransport, as the wiki's example shows them.
        let mut out = Vec::new();
        put_varint(&mut out, frame::WT_STREAM);
        put_varint(&mut out, 0);
        assert_eq!(out, [0x40, 0x41, 0x00]);
        out.clear();
        put_varint(&mut out, stream_type::WEBTRANSPORT);
        assert_eq!(out, [0x40, 0x54]);
    }

    #[test]
    fn frames_and_settings() {
        assert_eq!(frame(frame::DATA, b"abc"), [0x00, 0x03, b'a', b'b', b'c']);
        let payload = encode_settings(&[
            (setting::QPACK_MAX_TABLE_CAPACITY, 0),
            (setting::H3_DATAGRAM, 1),
            (setting::ENABLE_WEBTRANSPORT_DRAFT02, 1),
            (setting::WEBTRANSPORT_MAX_SESSIONS_DRAFT07, 16),
        ]);
        assert_eq!(payload, hex("0100 3301 ab603742 01 c0000000c671706a 10"));
        let s = parse_settings(&payload).unwrap();
        assert!(s.webtransport() && s.draft02());
        assert_eq!(s.draft07_sessions(), 16);
        // Chrome 149's settings, GREASE included (as eval-msquic logged them).
        let chrome = encode_settings(&[
            (0x1, 65536),
            (0x6, 16384),
            (0x7, 100),
            (0x33, 1),
            (0xffd277, 1),
            (0x2b603742, 1),
            (0x1c2a5644cf, 2232434543),
        ]);
        let s = parse_settings(&chrome).unwrap();
        assert!(is_grease(0x1c2a5644cf));
        assert!(s.webtransport() && s.draft02() && s.draft07_sessions() == 0);
        assert_eq!(s.get(0x1c2a5644cf), None);
        // Errors.
        let dup = encode_settings(&[(0x33, 1), (0x33, 1)]);
        assert_eq!(parse_settings(&dup).unwrap_err(), err::H3_SETTINGS_ERROR);
        let h2 = encode_settings(&[(0x02, 0)]);
        assert_eq!(parse_settings(&h2).unwrap_err(), err::H3_SETTINGS_ERROR);
        let big = encode_settings(&[(setting::H3_DATAGRAM, 2)]);
        assert_eq!(parse_settings(&big).unwrap_err(), err::H3_SETTINGS_ERROR);
        assert_eq!(parse_settings(&[0x33]).unwrap_err(), err::H3_FRAME_ERROR);
        let many: Vec<(u64, u64)> = (0..300).map(|i| (0x1000 + i, 0)).collect();
        assert_eq!(
            parse_settings(&encode_settings(&many)).unwrap_err(),
            err::H3_EXCESSIVE_LOAD
        );
        // No datagrams: not WebTransport.
        let s = parse_settings(&encode_settings(&[(0x2b603742, 1)])).unwrap();
        assert!(!s.webtransport());
    }

    #[test]
    fn prefixed_integers() {
        // RFC 7541 C.1: 10 with a 5-bit prefix, 1337 with a 5-bit prefix, 42 with 8 bits.
        for (flags, prefix, v, bytes) in [
            (0u8, 5u8, 10u64, "0a"),
            (0, 5, 1337, "1f9a0a"),
            (0, 8, 42, "2a"),
            (0xc0, 6, 63, "ff00"),
        ] {
            let mut out = Vec::new();
            put_qint(&mut out, flags, prefix, v);
            assert_eq!(out, hex(bytes));
            let mut pos = 0;
            assert_eq!(get_qint(&out, &mut pos, prefix), Some(v));
            assert_eq!(pos, out.len());
        }
        let mut pos = 0;
        assert_eq!(get_qint(&hex("1f9a"), &mut pos, 5), None);
        let mut pos = 0;
        assert_eq!(
            get_qint(&hex("1fffffffffffffffffffff7f"), &mut pos, 5),
            None
        );
    }

    #[test]
    fn huffman_rfc7541_appendix_c() {
        // Every Huffman-coded string of RFC 7541 C.4 and C.6.
        for (coded, text) in [
            ("f1e3c2e5f23a6ba0ab90f4ff", "www.example.com"),
            ("a8eb10649cbf", "no-cache"),
            ("25a849e95ba97d7f", "custom-key"),
            ("25a849e95bb8e8b4bf", "custom-value"),
            ("6402", "302"),
            ("aec3771a4b", "private"),
            (
                "d07abe941054d444a8200595040b8166e082a62d1bff",
                "Mon, 21 Oct 2013 20:13:21 GMT",
            ),
            (
                "9d29ad171863c78f0b97c8e9ae82ae43d3",
                "https://www.example.com",
            ),
            ("640eff", "307"),
            (
                "d07abe941054d444a8200595040b8166e084a62d1bff",
                "Mon, 21 Oct 2013 20:13:22 GMT",
            ),
            ("9bd9ab", "gzip"),
            (
                "94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
                "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
            ),
        ] {
            let mut out = Vec::new();
            huffman_decode(&hex(coded), &mut out, 1024).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), text);
        }
        // Every symbol, alone and padded with 1 bits, decodes back.
        for (sym, &(code, len)) in HUFFMAN.iter().enumerate().take(256) {
            let pad = (8 - len % 8) % 8;
            let bits = (u64::from(code) << pad) | ((1u64 << pad) - 1);
            let n = (len as usize + pad as usize) / 8;
            let bytes: Vec<u8> = (0..n).rev().map(|i| (bits >> (8 * i)) as u8).collect();
            let mut out = Vec::new();
            huffman_decode(&bytes, &mut out, 4).unwrap();
            assert_eq!(out, [sym as u8]);
        }
        let mut out = Vec::new();
        // EOS (30 bits of 1) is refused, as is padding of 8 bits or of a 0 bit.
        assert!(huffman_decode(&hex("ffffffff"), &mut out, 64).is_err());
        assert!(huffman_decode(&hex("f1e3c2e5f23a6ba0ab90f4ffff"), &mut out, 64).is_err());
        out.clear();
        assert!(huffman_decode(&hex("1e"), &mut out, 64).is_err());
        // The output bound.
        out.clear();
        assert!(huffman_decode(&hex("f1e3c2e5f23a6ba0ab90f4ff"), &mut out, 5).is_err());
    }

    #[test]
    fn static_table() {
        assert_eq!(static_entry(0), Some((":authority", "")));
        assert_eq!(static_entry(1), Some((":path", "/")));
        assert_eq!(static_entry(15), Some((":method", "CONNECT")));
        assert_eq!(static_entry(23), Some((":scheme", "https")));
        assert_eq!(static_entry(25), Some((":status", "200")));
        assert_eq!(static_entry(27), Some((":status", "404")));
        assert_eq!(static_entry(28), Some((":status", "503")));
        assert_eq!(
            static_entry(45),
            Some(("content-type", "application/javascript"))
        );
        assert_eq!(static_entry(63), Some((":status", "100")));
        assert_eq!(static_entry(68), Some((":status", "403")));
        assert_eq!(static_entry(90), Some(("origin", "")));
        assert_eq!(static_entry(98), Some(("x-frame-options", "sameorigin")));
        assert_eq!(static_entry(99), None);
    }

    #[test]
    fn field_sections() {
        // RFC 9204 B.1: a literal with a static name reference.
        let b1 = hex("0000 510b 2f69 6e64 6578 2e68 746d 6c");
        assert_eq!(
            decode_field_section(&b1, 16384).unwrap(),
            vec![(b":path".to_vec(), b"/index.html".to_vec())]
        );
        // RFC 9204 B.2 and B.4 reference the dynamic table: refused.
        for section in ["0381 10 11", "0500 80 c1 81"] {
            assert_eq!(
                decode_field_section(&hex(section), 16384).unwrap_err(),
                FieldError::Qpack
            );
        }
        // Each dynamic form, with a Required Insert Count of 0.
        for line in ["80", "10", "40 00", "00 00 00", "50 00"] {
            let mut s = hex("0000");
            s.extend(hex(line));
            let r = decode_field_section(&s, 16384);
            if line == "50 00" {
                // Static name reference to :authority with an empty value: fine.
                assert_eq!(r.unwrap(), vec![(b":authority".to_vec(), Vec::new())]);
            } else {
                assert_eq!(r.unwrap_err(), FieldError::Qpack, "{line}");
            }
        }
        // A round trip of a WebTransport CONNECT request through this encoder.
        let fields: Vec<(&[u8], &[u8])> = vec![
            (b":method", b"CONNECT"),
            (b":protocol", b"webtransport"),
            (b":scheme", b"https"),
            (b":authority", b"127.0.0.1:4433"),
            (b":path", b"/sb"),
            (b"origin", b"http://127.0.0.1:8766"),
            (b"sec-webtransport-http3-draft02", b"1"),
            (b"wt-available-protocols", b"\"switchboard\""),
        ];
        let enc = encode_field_section(&fields);
        // :method CONNECT and :scheme https are indexed lines.
        assert_eq!(&enc[..4], &[0x00, 0x00, 0xc0 | 15, 0x20 | 7]);
        let dec = decode_field_section(&enc, 16384).unwrap();
        assert_eq!(dec.len(), fields.len());
        for ((n, v), (dn, dv)) in fields.iter().zip(&dec) {
            assert_eq!((*n, *v), (dn.as_slice(), dv.as_slice()));
        }
        // A response: :status 200 indexed (0xd9).
        let enc = encode_field_section(&[(b":status", b"200")]);
        assert_eq!(enc, [0x00, 0x00, 0xd9]);
        // Huffman-coded name and value (a literal with a literal name, H on both).
        let mut s = hex("0000");
        s.push(0x28 | 0x06); // 001 N=0 H=1: the name "no-cache", 6 bytes of Huffman
        s.extend(hex("a8eb10649cbf"));
        s.push(0x80 | 0x03); // value "gzip", 3 bytes of Huffman
        s.extend(hex("9bd9ab"));
        assert_eq!(
            decode_field_section(&s, 16384).unwrap(),
            vec![(b"no-cache".to_vec(), b"gzip".to_vec())]
        );
        // Size bound: counted as RFC 9114 does.
        let enc = encode_field_section(&[(b"x-a", b"0123456789")]);
        assert!(decode_field_section(&enc, 3 + 10 + 32).is_ok());
        assert_eq!(
            decode_field_section(&enc, 3 + 10 + 31).unwrap_err(),
            FieldError::TooLarge
        );
        // Truncations are QPACK errors (the prefix alone is an empty section).
        assert!(decode_field_section(&b1[..2], 16384).unwrap().is_empty());
        for n in (1..2).chain(3..b1.len()) {
            assert!(decode_field_section(&b1[..n], 16384).is_err(), "{n}");
        }
    }

    #[test]
    fn qpack_streams() {
        // RFC 9204 B.2 to B.5 encoder instructions: all refused, Set Capacity 0 accepted.
        for instr in [
            "3fbd01",
            "c00f7777772e6578616d706c652e636f6d",
            "4a637573746f6d2d6b65790c637573746f6d2d76616c7565",
            "02",
            "810d637573746f6d2d76616c756532",
        ] {
            assert_eq!(
                check_encoder_stream(&hex(instr)),
                Err(err::QPACK_ENCODER_STREAM_ERROR)
            );
        }
        assert_eq!(check_encoder_stream(&[0x20, 0x20]), Ok(()));
        // Decoder instructions: Section Acknowledgment (B.2) and Insert Count Increment (B.3)
        // refused, Stream Cancellation (B.4) accepted, also split across reads.
        assert!(DecoderStreamCheck::default().feed(&hex("84")).is_err());
        assert!(DecoderStreamCheck::default().feed(&hex("01")).is_err());
        let mut d = DecoderStreamCheck::default();
        assert_eq!(d.feed(&hex("48")), Ok(()));
        assert_eq!(d.feed(&hex("7f")), Ok(()));
        assert_eq!(d.feed(&hex("ff")), Ok(()));
        assert_eq!(d.feed(&hex("01 48")), Ok(()));
        assert!(d.feed(&hex("7fffffffffffffffffffff")).is_err());
    }
    #[test]
    fn malformed_settings_and_field_prefixes() {
        for id in [0x21, 0x40, 0x12345] {
            assert_eq!(
                parse_settings(&encode_settings(&[(id, 1), (id, 2)])).unwrap_err(),
                err::H3_SETTINGS_ERROR
            );
        }
        assert_eq!(
            parse_settings(&encode_settings(&[(
                setting::ENABLE_WEBTRANSPORT_DRAFT02,
                2
            )]))
            .unwrap_err(),
            err::H3_SETTINGS_ERROR
        );
        for b in [&[0, 0x80][..], &[0, 0xff, 0x00]] {
            assert_eq!(decode_field_section(b, 1024), Err(FieldError::Qpack));
        }
        // Positive Base is irrelevant when no dynamic entries are used, and is legal.
        assert!(decode_field_section(&[0, 0x7f, 0x00], 1024).is_ok());
        // Malformed Huffman padding at exactly the decoded budget is still a QPACK error.
        let mut pos = 0;
        assert_eq!(
            get_string(&[0x82, 0x1f, 0xff], &mut pos, 7, 1),
            Err(FieldError::Qpack)
        );
        // The last continuation byte overflows the 62-bit QPACK implementation limit.
        let mut instruction = vec![0x7f];
        instruction.extend([0x80; 8]);
        instruction.push(0x40);
        assert_eq!(
            DecoderStreamCheck::default().feed(&instruction),
            Err(err::QPACK_DECODER_STREAM_ERROR)
        );
    }

    #[test]
    fn adversarial_codec_inputs_are_bounded() {
        let mut seed = 0x47a6_217bu32;
        for len in 0..=256 {
            for _ in 0..32 {
                let b: Vec<u8> = (0..len)
                    .map(|_| {
                        seed ^= seed << 13;
                        seed ^= seed >> 17;
                        seed ^= seed << 5;
                        seed as u8
                    })
                    .collect();
                let _ = get_varint(&b);
                let _ = parse_settings(&b);
                let _ = decode_field_section(&b, 256);
                let mut out = Vec::new();
                let _ = huffman_decode(&b, &mut out, 64);
                assert!(out.len() <= 64);
                let _ = DecoderStreamCheck::default().feed(&b);
                let _ = crate::wt::parse_string_list(&b);
                let _ = crate::wt::parse_string_item(&b);
                for prefix in 1..=8 {
                    let mut pos = 0;
                    let _ = get_qint(&b, &mut pos, prefix);
                    assert!(pos <= b.len());
                }
            }
        }
    }
}
