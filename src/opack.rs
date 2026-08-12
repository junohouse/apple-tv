//! OPACK — Apple's serialisation format, as carried inside a Companion frame.
//!
//! It is CoreUtils-internal and undocumented; what is here is the reverse-engineered subset
//! that a remote actually needs, matching pyatv's implementation. Everything Companion sends
//! and receives is one OPACK dictionary, so this and [`crate::frame`] are the whole wire.
//!
//! ```text
//!   0x01 0x02        true / false
//!   0x04             null
//!   0x05 + 16        UUID
//!   0x08..=0x2F      small int, value is tag - 8
//!   0x30..=0x33      int, 1/2/4/8 bytes little-endian
//!   0x35 0x36        f32 / f64
//!   0x40..=0x60      string, length is tag - 0x40, inline
//!   0x61..=0x64      string, 1/2/3/4 length bytes
//!   0x70..=0x90      data, length is tag - 0x70, inline
//!   0x91..=0x94      data, 1/2/4/8 length bytes
//!   0xA0..=0xC0      back-reference to the n-th object seen
//!   0xC1..=0xC4      the same, with 1/2/4/8 index bytes
//!   0xD0..=0xDF      array; low nibble is the count, 0xF means read until 0x03
//!   0xE0..=0xEF      dict;  low nibble is the count, 0xF means read until 0x03
//! ```
//!
//! # The back-reference table is why this is not a two-hour job
//!
//! Any object longer than one byte is appended to a table as it is encoded, and a later
//! occurrence is replaced by its index. Decoding has to build the identical table or every
//! index after the first repeat points at the wrong thing — and the failure is silent, because
//! a wrong index still decodes to *something*. The rules for what goes in the table are not
//! symmetric or obvious (booleans, null, small ints and the collections themselves are excluded
//! on decode; on encode the test is the encoded length), so both halves here follow pyatv
//! exactly rather than being tidied into something that looks more principled.

use std::collections::BTreeMap;

/// One OPACK value. Deliberately smaller than `serde_json::Value`: Companion never sends a
/// float or a UUID where it matters to us, but it does send raw byte strings constantly — every
/// pairing TLV arrives as one — and JSON has nowhere to put those.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Null,
    Bool(bool),
    Int(u64),
    Str(String),
    Data(Vec<u8>),
    Uuid([u8; 16]),
    Arr(Vec<Val>),
    Dict(BTreeMap<String, Val>),
}

impl Val {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Val::Data(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Val::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Val> {
        match self {
            Val::Dict(m) => m.get(key),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Val]> {
        match self {
            Val::Arr(a) => Some(a),
            _ => None,
        }
    }
}

/// Build a dictionary without ceremony at the call site.
pub fn dict<const N: usize>(pairs: [(&str, Val); N]) -> Val {
    Val::Dict(
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

pub fn s(v: &str) -> Val {
    Val::Str(v.to_string())
}

// ---------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------

pub fn pack(value: &Val) -> Vec<u8> {
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut out = Vec::new();
    encode(value, &mut seen, &mut out);
    out
}

fn encode(value: &Val, seen: &mut Vec<Vec<u8>>, out: &mut Vec<u8>) {
    let mut body = Vec::new();
    match value {
        Val::Null => body.push(0x04),
        Val::Bool(true) => body.push(0x01),
        Val::Bool(false) => body.push(0x02),
        Val::Uuid(u) => {
            body.push(0x05);
            body.extend_from_slice(u);
        }
        Val::Int(i) => {
            let i = *i;
            if i < 0x28 {
                body.push(i as u8 + 8);
            } else if i <= 0xFF {
                body.push(0x30);
                body.push(i as u8);
            } else if i <= 0xFFFF {
                body.push(0x31);
                body.extend_from_slice(&(i as u16).to_le_bytes());
            } else if i <= 0xFFFF_FFFF {
                body.push(0x32);
                body.extend_from_slice(&(i as u32).to_le_bytes());
            } else {
                body.push(0x33);
                body.extend_from_slice(&i.to_le_bytes());
            }
        }
        Val::Str(text) => {
            let b = text.as_bytes();
            match b.len() {
                n if n <= 0x20 => body.push(0x40 + n as u8),
                n if n <= 0xFF => {
                    body.push(0x61);
                    body.push(n as u8);
                }
                n if n <= 0xFFFF => {
                    body.push(0x62);
                    body.extend_from_slice(&(n as u16).to_le_bytes());
                }
                n if n <= 0xFF_FFFF => {
                    body.push(0x63);
                    body.extend_from_slice(&(n as u32).to_le_bytes()[..3]);
                }
                n => {
                    body.push(0x64);
                    body.extend_from_slice(&(n as u32).to_le_bytes());
                }
            }
            body.extend_from_slice(b);
        }
        Val::Data(d) => {
            match d.len() {
                n if n <= 0x20 => body.push(0x70 + n as u8),
                n if n <= 0xFF => {
                    body.push(0x91);
                    body.push(n as u8);
                }
                n if n <= 0xFFFF => {
                    body.push(0x92);
                    body.extend_from_slice(&(n as u16).to_le_bytes());
                }
                n => {
                    body.push(0x93);
                    body.extend_from_slice(&(n as u32).to_le_bytes());
                }
            }
            body.extend_from_slice(d);
        }
        // Collections encode their children through the same table, so the recursion has to
        // share `seen` rather than starting a fresh one per level.
        Val::Arr(items) => {
            body.push(0xD0 + items.len().min(0xF) as u8);
            for item in items {
                encode(item, seen, &mut body);
            }
            if items.len() >= 0xF {
                body.push(0x03);
            }
        }
        Val::Dict(map) => {
            body.push(0xE0 + map.len().min(0xF) as u8);
            for (k, v) in map {
                encode(&Val::Str(k.clone()), seen, &mut body);
                encode(v, seen, &mut body);
            }
            if map.len() >= 0xF {
                body.push(0x03);
            }
        }
    }

    // Already sent once: send its index instead. Checked on the *encoded* bytes, which is what
    // makes two equal strings one entry and an int and a one-byte string distinct ones.
    if let Some(index) = seen.iter().position(|prev| *prev == body) {
        if index < 0x21 {
            out.push(0xA0 + index as u8);
        } else if index <= 0xFF {
            out.push(0xC1);
            out.push(index as u8);
        } else {
            out.push(0xC2);
            out.extend_from_slice(&(index as u16).to_le_bytes());
        }
        return;
    }
    if body.len() > 1 {
        seen.push(body.clone());
    }
    out.extend_from_slice(&body);
}

// ---------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------

pub fn unpack(data: &[u8]) -> Result<Val, String> {
    let mut seen: Vec<Val> = Vec::new();
    let (value, _) = decode(data, &mut seen)?;
    Ok(value)
}

fn need(data: &[u8], n: usize) -> Result<(), String> {
    if data.len() < n {
        return Err(format!("opack: wanted {n} bytes, {} left", data.len()));
    }
    Ok(())
}

fn le(data: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, b) in data.iter().enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    v
}

fn decode<'a>(data: &'a [u8], seen: &mut Vec<Val>) -> Result<(Val, &'a [u8]), String> {
    need(data, 1)?;
    let tag = data[0];
    let rest = &data[1..];

    // Which values join the back-reference table is not symmetric with encoding and is not
    // guessable — it is what the format does. Booleans, null, small ints and whole collections
    // stay out; everything else goes in, in the order it was decoded.
    let (value, remaining, remember) = match tag {
        0x01 => (Val::Bool(true), rest, false),
        0x02 => (Val::Bool(false), rest, false),
        0x04 => (Val::Null, rest, false),
        0x05 => {
            need(rest, 16)?;
            let mut u = [0u8; 16];
            u.copy_from_slice(&rest[..16]);
            (Val::Uuid(u), &rest[16..], true)
        }
        0x08..=0x2F => (Val::Int((tag - 8) as u64), rest, false),
        0x30..=0x33 => {
            let n = 1usize << (tag & 0xF);
            need(rest, n)?;
            (Val::Int(le(&rest[..n])), &rest[n..], true)
        }
        // Floats are decoded so a stray one does not desynchronise the stream, but they are
        // kept as their bit pattern: nothing a remote sends or reads is a float, and inventing
        // a variant for it would put a `f64` in every match in this driver for no caller.
        0x35 => {
            need(rest, 4)?;
            (Val::Int(le(&rest[..4])), &rest[4..], true)
        }
        0x36 => {
            need(rest, 8)?;
            (Val::Int(le(&rest[..8])), &rest[8..], true)
        }
        0x40..=0x60 => {
            let n = (tag - 0x40) as usize;
            need(rest, n)?;
            let text = String::from_utf8_lossy(&rest[..n]).into_owned();
            (Val::Str(text), &rest[n..], true)
        }
        0x61..=0x64 => {
            let w = (tag & 0xF) as usize;
            need(rest, w)?;
            let n = le(&rest[..w]) as usize;
            need(&rest[w..], n)?;
            let text = String::from_utf8_lossy(&rest[w..w + n]).into_owned();
            (Val::Str(text), &rest[w + n..], true)
        }
        0x70..=0x90 => {
            let n = (tag - 0x70) as usize;
            need(rest, n)?;
            (Val::Data(rest[..n].to_vec()), &rest[n..], true)
        }
        0x91..=0x94 => {
            let w = 1usize << ((tag & 0xF) - 1);
            need(rest, w)?;
            let n = le(&rest[..w]) as usize;
            need(&rest[w..], n)?;
            (Val::Data(rest[w..w + n].to_vec()), &rest[w + n..], true)
        }
        0xA0..=0xC0 => {
            let i = (tag - 0xA0) as usize;
            let v = seen
                .get(i)
                .ok_or_else(|| format!("opack: back-reference {i} past the end"))?
                .clone();
            (v, rest, false)
        }
        0xC1..=0xC4 => {
            let w = (tag - 0xC0) as usize;
            need(rest, w)?;
            let i = le(&rest[..w]) as usize;
            let v = seen
                .get(i)
                .ok_or_else(|| format!("opack: back-reference {i} past the end"))?
                .clone();
            (v, &rest[w..], false)
        }
        0xD0..=0xDF => {
            let count = (tag & 0xF) as usize;
            let mut items = Vec::new();
            let mut ptr = rest;
            if count == 0xF {
                loop {
                    need(ptr, 1)?;
                    if ptr[0] == 0x03 {
                        ptr = &ptr[1..];
                        break;
                    }
                    let (v, next) = decode(ptr, seen)?;
                    items.push(v);
                    ptr = next;
                }
            } else {
                for _ in 0..count {
                    let (v, next) = decode(ptr, seen)?;
                    items.push(v);
                    ptr = next;
                }
            }
            (Val::Arr(items), ptr, false)
        }
        0xE0..=0xEF => {
            let count = (tag & 0xF) as usize;
            let mut map = BTreeMap::new();
            let mut ptr = rest;
            let mut one = |ptr: &mut &[u8], seen: &mut Vec<Val>| -> Result<(), String> {
                let (k, next) = decode(ptr, seen)?;
                let (v, next) = decode(next, seen)?;
                // A non-string key is legal OPACK and meaningless to us. Rendering it rather
                // than refusing keeps one odd field from discarding a whole reply.
                let key = match k {
                    Val::Str(text) => text,
                    other => format!("{other:?}"),
                };
                map.insert(key, v);
                *ptr = next;
                Ok(())
            };
            if count == 0xF {
                loop {
                    need(ptr, 1)?;
                    if ptr[0] == 0x03 {
                        ptr = &ptr[1..];
                        break;
                    }
                    one(&mut ptr, seen)?;
                }
            } else {
                for _ in 0..count {
                    one(&mut ptr, seen)?;
                }
            }
            (Val::Dict(map), ptr, false)
        }
        other => return Err(format!("opack: unknown tag {other:#04x}")),
    };

    if remember && !seen.contains(&value) {
        seen.push(value.clone());
    }
    Ok((value, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(v: Val) {
        let packed = pack(&v);
        let back = unpack(&packed).expect("decodes");
        assert_eq!(back, v, "packed as {packed:02x?}");
    }

    #[test]
    fn scalars_survive_a_round_trip() {
        round(Val::Null);
        round(Val::Bool(true));
        round(Val::Bool(false));
        for i in [0u64, 1, 0x27, 0x28, 0xFF, 0x100, 0xFFFF, 0x1_0000, 0xFFFF_FFFF] {
            round(Val::Int(i));
        }
        round(Val::Uuid([7u8; 16]));
    }

    /// The tag encodes the length up to 0x20, then a separate width byte takes over. Both sides
    /// of that boundary, because an off-by-one there is a frame that decodes as garbage.
    #[test]
    fn strings_and_data_cross_their_length_boundaries() {
        for n in [0usize, 1, 0x1F, 0x20, 0x21, 0xFF, 0x100, 0x1234] {
            round(Val::Str("a".repeat(n)));
            round(Val::Data(vec![0xABu8; n]));
        }
    }

    /// A collection of 15 or more switches to a terminator instead of an inline count.
    #[test]
    fn collections_cross_the_endless_boundary() {
        for n in [0usize, 1, 14, 15, 16, 40] {
            round(Val::Arr((0..n).map(|i| Val::Int(i as u64)).collect()));
            round(Val::Dict(
                (0..n)
                    .map(|i| (format!("k{i}"), Val::Int(i as u64)))
                    .collect(),
            ));
        }
    }

    /// The back-reference table is the part that fails silently when it is wrong.
    ///
    /// A repeated value encodes as an index, and the decoder has to have built the same table in
    /// the same order to resolve it. If it has not, the index still points at *something* and the
    /// frame decodes to plausible nonsense rather than an error — so this asserts both that the
    /// repeat is actually compressed and that it comes back as the original value.
    #[test]
    fn a_repeated_value_becomes_a_back_reference_and_resolves_to_itself() {
        let long = "com.apple.tvremoteservices";
        let v = Val::Arr(vec![s(long), s(long), s(long)]);
        let packed = pack(&v);

        let once = pack(&Val::Arr(vec![s(long)]));
        assert!(
            packed.len() < once.len() + 2 * long.len(),
            "the repeats were not compressed: {} bytes",
            packed.len()
        );
        assert_eq!(unpack(&packed).unwrap(), v);
    }

    /// Nested collections share one table with their parent. Encoding each level against a fresh
    /// table produces indices the decoder resolves against a different one.
    #[test]
    fn nesting_shares_one_back_reference_table() {
        let long = "FetchLaunchableApplicationsEvent";
        let v = dict([
            ("_i", s(long)),
            ("_c", dict([("again", s(long)), ("n", Val::Int(3))])),
        ]);
        round(v);
    }

    /// The real thing: what a button press actually looks like on the wire.
    #[test]
    fn a_hid_command_round_trips() {
        let v = dict([
            ("_i", s("_hidC")),
            ("_t", Val::Int(2)),
            ("_x", Val::Int(12345)),
            ("_c", dict([("_hBtS", Val::Int(1)), ("_hidC", Val::Int(6))])),
        ]);
        round(v);
    }

    /// Truncation is an error, not a panic. A short read off a socket is normal — the frame
    /// simply has not all arrived — and this is the path that decides so.
    #[test]
    fn a_truncated_frame_is_refused_rather_than_panicking() {
        let packed = pack(&dict([("_i", s("_systemInfo")), ("_c", Val::Int(9))]));
        for cut in 1..packed.len() {
            // Any prefix either decodes (a shorter valid value) or errors. Neither panics.
            let _ = unpack(&packed[..cut]);
        }
        assert!(unpack(&[]).is_err(), "an empty frame has no value in it");
    }
}
