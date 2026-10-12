/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
  Claude Fable 5.1 <noreply@anthropic.com>
*/

//! WebTransport over HTTP/3 (draft-ietf-webtrans-http3), the pure parts: error codes and the
//! mapping of application codes into the HTTP/3 space, capsules, the exporter context, and the
//! Structured Field values (RFC 9651) of protocol negotiation. The sessions themselves are in
//! `h3conn`.

use crate::h3::{put_varint, VARINT_MAX};

/// HTTP/3 error codes the WebTransport draft defines.
pub mod err {
    /// A data stream refused because its session does not exist (yet).
    pub(crate) const WT_BUFFERED_STREAM_REJECTED: u64 = 0x3994_bd84;
    /// A data stream aborted because its session ended.
    pub(crate) const WT_SESSION_GONE: u64 = 0x170d_7b68;
    /// The server's response selected a protocol the client did not offer (draft-15 and later;
    /// drafts 13 and 14 have the client ignore such a `WT-Protocol`).
    pub(crate) const WT_ALPN_ERROR: u64 = 0x0817_b3dd;
    /// The peer's SETTINGS or transport parameters lack what WebTransport needs (draft-15 and
    /// later; older peers read it as an unknown code).
    pub(crate) const WT_REQUIREMENTS_NOT_MET: u64 = 0x212c_0d48;
}

/// Capsule types (RFC 9297 and the draft).
#[allow(dead_code)]
pub mod capsule {
    pub(crate) const DATAGRAM: u64 = 0x00;
    pub(crate) const WT_CLOSE_SESSION: u64 = 0x2843;
    pub(crate) const WT_DRAIN_SESSION: u64 = 0x78ae;
    /// Defined by the HTTP/2 draft only; receiving one over HTTP/3 is a session error.
    pub(crate) const WT_MAX_STREAM_DATA: u64 = 0x190b_4d3e;
    /// Defined by the HTTP/2 draft only; receiving one over HTTP/3 is a session error.
    pub(crate) const WT_STREAM_DATA_BLOCKED: u64 = 0x190b_4d42;
}

/// The longest message of a WT_CLOSE_SESSION capsule.
pub(crate) const MAX_CLOSE_MESSAGE: usize = 1024;

/// The first HTTP/3 error code of the WebTransport application error codes.
pub(crate) const APP_CODE_FIRST: u64 = 0x52e4_a40f_a8db;
/// The last one (the code of 0xffffffff).
pub(crate) const APP_CODE_LAST: u64 = 0x52e5_ac98_3162;

/// The HTTP/3 error code that carries the WebTransport application error code `code`: `first +
/// n + floor(n / 0x1e)`, which skips the reserved codepoints of HTTP/3.
pub fn app_to_h3(code: u32) -> u64 {
    let n = u64::from(code);
    APP_CODE_FIRST + n + n / 0x1e
}

/// The WebTransport application error code that the HTTP/3 error code `h3` carries; None outside
/// the range and for the reserved codepoints within it (0x1f * N + 0x21).
pub fn h3_to_app(h3: u64) -> Option<u32> {
    if !(APP_CODE_FIRST..=APP_CODE_LAST).contains(&h3) || (h3 - 0x21) % 0x1f == 0 {
        return None;
    }
    let shifted = h3 - APP_CODE_FIRST;
    u32::try_from(shifted - shifted / 0x1f).ok()
}

/// The TLS exporter label of WebTransport's keying material exporter.
pub(crate) const EXPORTER_LABEL: &[u8] = b"EXPORTER-WebTransport";

/// The TLS exporter context of a session's exporter for the application's `label` and
/// `context` (draft section "Use of Keying Material Exporters"): the session ID as a 64-bit
/// big-endian integer, then the label and the context, each preceded by its length in one byte.
/// None when the label or the context is longer than 255 bytes.
pub fn exporter_context(session_id: u64, label: &[u8], context: &[u8]) -> Option<Vec<u8>> {
    let label_len = u8::try_from(label.len()).ok()?;
    let context_len = u8::try_from(context.len()).ok()?;
    let mut out = Vec::with_capacity(10 + label.len() + context.len());
    out.extend_from_slice(&session_id.to_be_bytes());
    out.push(label_len);
    out.extend_from_slice(label);
    out.push(context_len);
    out.extend_from_slice(context);
    Some(out)
}

/// Appends a capsule: type, length, payload.
pub fn put_capsule(out: &mut Vec<u8>, capsule_type: u64, payload: &[u8]) {
    debug_assert!(capsule_type <= VARINT_MAX);
    put_varint(out, capsule_type);
    put_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// `message` cut to at most `max` bytes at a UTF-8 character boundary (it is UTF-8 already, or
/// cut at a byte boundary otherwise).
pub fn truncate_utf8(message: &[u8], max: usize) -> &[u8] {
    if message.len() <= max {
        return message;
    }
    let mut n = max;
    if std::str::from_utf8(message).is_ok() {
        while n > 0 && (message[n] & 0xc0) == 0x80 {
            n -= 1;
        }
    }
    &message[..n]
}

/// The WT_CLOSE_SESSION capsule for `code` and `message` (cut to 1024 bytes).
pub fn close_capsule(code: u32, message: &[u8]) -> Vec<u8> {
    let message = truncate_utf8(message, MAX_CLOSE_MESSAGE);
    let mut payload = Vec::with_capacity(4 + message.len());
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(message);
    let mut out = Vec::new();
    put_capsule(&mut out, capsule::WT_CLOSE_SESSION, &payload);
    out
}

/// The WT_DRAIN_SESSION capsule.
pub fn drain_capsule() -> Vec<u8> {
    let mut out = Vec::new();
    put_capsule(&mut out, capsule::WT_DRAIN_SESSION, &[]);
    out
}

// ---------------------------------------------------------------------------------------------
// Structured Field values (RFC 9651), as far as protocol negotiation needs them:
// WT-Available-Protocols is a List and WT-Protocol an Item, and the only valid value type of
// either is a String; anything else makes the whole field ignored, and parameters are ignored.

struct Sf<'a> {
    b: &'a [u8],
    i: usize,
}

impl Sf<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.i += 1;
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }

    fn string(&mut self) -> Option<String> {
        if self.peek()? != b'"' {
            return None;
        }
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'\\' => {
                    let e = self.peek()?;
                    if e != b'"' && e != b'\\' {
                        return None;
                    }
                    self.i += 1;
                    out.push(e as char);
                }
                b'"' => return Some(out),
                0x20..=0x7e => out.push(c as char),
                _ => return None,
            }
        }
    }

    fn is_tchar(c: u8) -> bool {
        c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
    }

    fn number(&mut self, integer_only: bool) -> Option<()> {
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let digits = self.i - start;
        if digits == 0 || digits > 15 {
            return None;
        }
        if self.peek() == Some(b'.') {
            if integer_only || digits > 12 {
                return None;
            }
            self.i += 1;
            let start = self.i;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
            if !(1..=3).contains(&(self.i - start)) {
                return None;
            }
        }
        Some(())
    }

    fn display_string(&mut self) -> Option<()> {
        self.i += 1; // %
        if self.peek()? != b'"' {
            return None;
        }
        self.i += 1;
        let mut decoded = Vec::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return std::str::from_utf8(&decoded).ok().map(|_| ()),
                b'%' => {
                    let mut octet = 0;
                    for _ in 0..2 {
                        let digit = match self.peek()? {
                            c @ b'0'..=b'9' => c - b'0',
                            c @ b'a'..=b'f' => c - b'a' + 10,
                            _ => return None,
                        };
                        self.i += 1;
                        octet = octet * 16 + digit;
                    }
                    decoded.push(octet);
                }
                0x20..=0x7e => decoded.push(c),
                _ => return None,
            }
        }
    }

    /// Any bare item (the values of parameters), validated and discarded.
    fn bare_item(&mut self) -> Option<()> {
        match self.peek()? {
            b'"' => self.string().map(|_| ()),
            b'-' | b'0'..=b'9' => self.number(false),
            b'?' => {
                self.i += 1;
                matches!(self.peek(), Some(b'0' | b'1')).then(|| self.i += 1)
            }
            b':' => {
                self.i += 1;
                let start = self.i;
                while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
                {
                    self.i += 1;
                }
                let digits = self.i - start;
                let start = self.i;
                while self.peek() == Some(b'=') {
                    self.i += 1;
                }
                let padding = self.i - start;
                // Missing padding and nonzero pad bits are tolerated by RFC 9651 4.2.7.
                if digits % 4 == 1 || padding > 2 || (padding > 0 && (digits + padding) % 4 != 0) {
                    return None;
                }
                (self.peek()? == b':').then(|| self.i += 1)
            }
            b'@' => {
                self.i += 1;
                self.number(true)
            }
            b'%' => self.display_string(),
            c if c.is_ascii_alphabetic() || c == b'*' => {
                while matches!(self.peek(), Some(c) if Self::is_tchar(c) || c == b':' || c == b'/')
                {
                    self.i += 1;
                }
                Some(())
            }
            _ => None,
        }
    }

    fn parameters(&mut self) -> Option<()> {
        while self.peek() == Some(b';') {
            self.i += 1;
            self.skip_sp();
            let c = self.peek()?;
            if !(c.is_ascii_lowercase() || c == b'*') {
                return None;
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-.*".contains(&c))
            {
                self.i += 1;
            }
            if self.peek() == Some(b'=') {
                self.i += 1;
                self.bare_item()?;
            }
        }
        Some(())
    }

    /// An item whose bare item is a String, with its parameters.
    fn string_item(&mut self) -> Option<String> {
        let s = self.string()?;
        self.parameters()?;
        Some(s)
    }
}

/// Parses a List whose members are all Strings (WT-Available-Protocols); None when the field is
/// malformed or holds another type, in which case it is ignored.
pub fn parse_string_list(value: &[u8]) -> Option<Vec<String>> {
    let mut p = Sf { b: value, i: 0 };
    p.skip_sp();
    let mut out = Vec::new();
    if p.peek().is_none() {
        return Some(out);
    }
    loop {
        out.push(p.string_item()?);
        p.skip_ows();
        match p.peek() {
            None => break,
            Some(b',') => {
                p.i += 1;
                p.skip_ows();
                p.peek()?;
            }
            Some(_) => return None,
        }
    }
    // Trailing spaces are part of the field's whitespace, which the parser discards.
    Some(out)
}

/// Parses an Item that is a String (WT-Protocol); None when malformed or of another type.
pub fn parse_string_item(value: &[u8]) -> Option<String> {
    let mut p = Sf { b: value, i: 0 };
    p.skip_sp();
    let s = p.string_item()?;
    p.skip_sp();
    p.peek().is_none().then_some(s)
}

/// Whether `s` can be a String (printable ASCII).
pub fn is_sf_string(s: &[u8]) -> bool {
    s.iter().all(|c| (0x20..=0x7e).contains(c))
}

/// `s` (printable ASCII) as a String.
pub fn sf_string(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for &c in s {
        if c == b'"' || c == b'\\' {
            out.push('\\');
        }
        out.push(c as char);
    }
    out.push('"');
    out
}

/// `items` (printable ASCII each) as a List of Strings.
pub fn sf_string_list(items: &[Vec<u8>]) -> String {
    items
        .iter()
        .map(|s| sf_string(s))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_codes() {
        // The values of the binding page.
        assert_eq!(app_to_h3(0), 0x52e4a40fa8db);
        assert_eq!(app_to_h3(5), 0x52e4a40fa8e0);
        assert_eq!(app_to_h3(14), 0x52e4a40fa8e9);
        assert_eq!(app_to_h3(29), 0x52e4a40fa8f8);
        assert_eq!(app_to_h3(30), 0x52e4a40fa8fa);
        assert_eq!(app_to_h3(33), 0x52e4a40fa8fd);
        assert_eq!(app_to_h3(36), 0x52e4a40fa900);
        assert_eq!(app_to_h3(42), 0x52e4a40fa906);
        assert_eq!(app_to_h3(255), 0x52e4a40fa9e2);
        assert_eq!(app_to_h3(u32::MAX), APP_CODE_LAST);
        // The reserved codepoint between 29 and 30, and the ones at both ends of the range.
        assert_eq!(h3_to_app(0x52e4a40fa8f9), None);
        assert!(crate::h3::is_grease(0x52e4a40fa8f9));
        assert_eq!(h3_to_app(APP_CODE_FIRST - 1), None);
        assert_eq!(h3_to_app(APP_CODE_LAST + 1), None);
        assert_eq!(h3_to_app(0x100), None);
        assert_eq!(h3_to_app(err::WT_SESSION_GONE), None);
        // Both ways, across a stretch of codes, the ends and reserved points included.
        for n in (0..100_000u32).chain(u32::MAX - 100..=u32::MAX) {
            let h = app_to_h3(n);
            assert!(!crate::h3::is_grease(h), "{n}");
            assert_eq!(h3_to_app(h), Some(n));
        }
        let mut reserved = 0;
        for h in APP_CODE_FIRST..APP_CODE_FIRST + 10_000 {
            match h3_to_app(h) {
                Some(n) => assert_eq!(app_to_h3(n), h),
                None => reserved += 1,
            }
        }
        // One in every 0x1f, the first at offset 0x1e (the one between 29 and 30).
        assert_eq!(reserved, (10_000 - 0x1e - 1) / 0x1f + 1);
    }

    #[test]
    fn exporter_contexts() {
        // The "Exporter" vectors of the binding page.
        assert_eq!(
            EXPORTER_LABEL,
            [
                0x45, 0x58, 0x50, 0x4F, 0x52, 0x54, 0x45, 0x52, 0x2D, 0x57, 0x65, 0x62, 0x54, 0x72,
                0x61, 0x6E, 0x73, 0x70, 0x6F, 0x72, 0x74
            ]
        );
        let ctx0 = exporter_context(0, b"switchboard-ident", b"").unwrap();
        assert_eq!(
            ctx0,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x73, 0x77, 0x69, 0x74, 0x63,
                0x68, 0x62, 0x6F, 0x61, 0x72, 0x64, 0x2D, 0x69, 0x64, 0x65, 0x6E, 0x74, 0x00
            ]
        );
        assert_eq!(ctx0.len(), 27);
        let ctx4 = exporter_context(4, b"switchboard-ident", b"").unwrap();
        assert_eq!(&ctx4[..8], &[0, 0, 0, 0, 0, 0, 0, 4]);
        assert_eq!(&ctx4[8..], &ctx0[8..]);
        let ctx = exporter_context(0x0102030405060708, b"l", &[9, 9]).unwrap();
        assert_eq!(ctx, [1, 2, 3, 4, 5, 6, 7, 8, 1, b'l', 2, 9, 9]);
        assert!(exporter_context(0, &[0; 256], b"").is_none());
        assert!(exporter_context(0, b"", &[0; 256]).is_none());
        assert!(exporter_context(0, &[0; 255], &[0; 255]).is_some());
    }

    #[test]
    fn capsules() {
        // As the evaluation's client sent it: code 33, "going away".
        assert_eq!(
            close_capsule(33, b"going away"),
            [
                0x68, 0x43, 0x0e, 0x00, 0x00, 0x00, 0x21, b'g', b'o', b'i', b'n', b'g', b' ', b'a',
                b'w', b'a', b'y'
            ]
        );
        assert_eq!(drain_capsule(), [0x80, 0x00, 0x78, 0xae, 0x00]);
        // The message is cut to 1024 bytes at a character boundary.
        let long = "é".repeat(600);
        let c = close_capsule(7, long.as_bytes());
        let (len, n) = crate::h3::get_varint(&c[2..]).unwrap();
        assert_eq!(len, 4 + 1024);
        assert!(std::str::from_utf8(&c[2 + n + 4..]).is_ok());
        let odd = format!("x{}", "é".repeat(600));
        let c = close_capsule(7, odd.as_bytes());
        let (len, _) = crate::h3::get_varint(&c[2..]).unwrap();
        assert_eq!(len, 4 + 1023);
    }

    #[test]
    fn structured_fields() {
        let list = |s: &str| parse_string_list(s.as_bytes());
        assert_eq!(list("\"switchboard\""), Some(vec!["switchboard".into()]));
        assert_eq!(
            list("\"a\", \"b\";q=0.5;x, \"c\\\"d\""),
            Some(vec!["a".into(), "b".into(), "c\"d".into()])
        );
        assert_eq!(list(""), Some(vec![]));
        assert_eq!(list("  \"a\"  "), Some(vec!["a".into()]));
        assert_eq!(list("\"a\",\t\"b\""), Some(vec!["a".into(), "b".into()]));
        assert_eq!(
            list("\"a\";p=:aGk=:;b=?1;d=@12;s=%\"x\";t=tok/en"),
            Some(vec!["a".into()])
        );
        // Another type, an inner list, a trailing comma, junk: the field is ignored.
        for bad in [
            "switchboard",
            "(\"a\")",
            "\"a\",",
            "\"a\" x",
            "\"a",
            "\"\\x\"",
            "1",
            "\"a\";P=1",
            "\"é\"",
        ] {
            assert_eq!(list(bad), None, "{bad}");
        }
        let item = |s: &str| parse_string_item(s.as_bytes());
        assert_eq!(item("\"switchboard\""), Some("switchboard".into()));
        assert_eq!(item("\"switchboard\";v=2"), Some("switchboard".into()));
        assert_eq!(item("\"a\", \"b\""), None);
        assert_eq!(item("token"), None);
        // Encoding.
        assert_eq!(sf_string(b"switchboard"), "\"switchboard\"");
        assert_eq!(sf_string(b"a\"b\\"), "\"a\\\"b\\\\\"");
        assert_eq!(
            sf_string_list(&[b"a".to_vec(), b"b c".to_vec()]),
            "\"a\", \"b c\""
        );
        assert!(is_sf_string(b"x y") && !is_sf_string(b"\x7f") && !is_sf_string("é".as_bytes()));
        let round = sf_string_list(&[b"q\"\\".to_vec(), b"switchboard".to_vec()]);
        assert_eq!(
            parse_string_list(round.as_bytes()),
            Some(vec!["q\"\\".into(), "switchboard".into()])
        );
    }
    #[test]
    fn structured_parameter_grammar_and_truncations() {
        for param in [
            "@-123",
            "999999999999999",
            "-999999999999.999",
            ":aGk:",
            "%\"%c3%a9\"",
            "%\"back\\slash\"",
            "?0",
        ] {
            let field = format!("\"switchboard\";p={param}");
            assert!(parse_string_item(field.as_bytes()).is_some(), "{field}");
        }
        for param in [
            "@@1",
            "@?1",
            "@1.0",
            "-.",
            "1..0",
            "1.",
            "1.0000",
            "1234567890123456",
            "1234567890123.0",
            ":a:",
            ":a=b:",
            ":aGk===:",
            "%\"%FF\"",
            "%\"%ff\"",
            "%\"%c3\"",
            "%\"%xx\"",
        ] {
            let field = format!("\"switchboard\";p={param}");
            assert_eq!(parse_string_item(field.as_bytes()), None, "{field}");
            assert_eq!(parse_string_list(field.as_bytes()), None, "{field}");
        }
        // The former recursive date parser could exhaust a worker's stack at the field limit.
        let recursive = format!("\"switchboard\";p={}0", "@".repeat(16_000));
        assert_eq!(parse_string_item(recursive.as_bytes()), None);
        for field in [r#""a\"b";p=%"%c3%a9""#, r#""a";p=:aGk=:, "b";q=@12"#] {
            for end in 0..=field.len() {
                let _ = parse_string_list(&field.as_bytes()[..end]);
                let _ = parse_string_item(&field.as_bytes()[..end]);
            }
        }
    }
}
