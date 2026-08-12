//! TLV8 — the type/length/value encoding HAP's pairing messages are made of.
//!
//! One byte of type, one byte of length, then that many bytes. A value longer than 255 bytes is
//! split across repeated entries of the same type, which has to be reassembled on read: an SRP
//! public key is 384 bytes and therefore always arrives in two fragments. Missing that is the
//! classic first bug here — the key looks like it decoded, it is simply the first 255 bytes of
//! one, and the proof that follows never matches.

/// Types from the HAP specification's pairing table.
pub const METHOD: u8 = 0x00;
pub const IDENTIFIER: u8 = 0x01;
pub const SALT: u8 = 0x02;
pub const PUBLIC_KEY: u8 = 0x03;
pub const PROOF: u8 = 0x04;
pub const ENCRYPTED_DATA: u8 = 0x05;
pub const STATE: u8 = 0x06;
pub const ERROR: u8 = 0x07;
pub const SIGNATURE: u8 = 0x0A;
/// Apple's own, outside the published table. Carries an OPACK blob naming the controller.
pub const NAME: u8 = 0x11;

pub fn encode(items: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (ty, value) in items {
        // Fragmented at 255, which is the only way to say anything longer.
        if value.is_empty() {
            out.push(*ty);
            out.push(0);
            continue;
        }
        for chunk in value.chunks(255) {
            out.push(*ty);
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
        }
    }
    out
}

/// Every entry, with fragments of the same type joined back together.
pub fn decode(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let ty = data[i];
        let len = data[i + 1] as usize;
        if i + 2 + len > data.len() {
            break; // truncated: keep what parsed rather than discarding the lot
        }
        let value = &data[i + 2..i + 2 + len];
        // Consecutive entries of one type are one value split at 255. Non-consecutive ones are
        // genuinely separate, which is why this looks at the last entry rather than searching.
        match out.last_mut() {
            Some((prev, buf)) if *prev == ty => buf.extend_from_slice(value),
            _ => out.push((ty, value.to_vec())),
        }
        i += 2 + len;
    }
    out
}

pub fn get(items: &[(u8, Vec<u8>)], ty: u8) -> Option<&[u8]> {
    items
        .iter()
        .find(|(t, _)| *t == ty)
        .map(|(_, v)| v.as_slice())
}

/// The device's refusal, in words rather than a number.
///
/// Worth spelling out: these arrive during pairing, in front of somebody holding a remote and
/// looking at a PIN on a television, and "error 2" tells them nothing about what to do next.
pub fn error(items: &[(u8, Vec<u8>)]) -> Option<String> {
    let code = get(items, ERROR)?.first().copied()?;
    Some(match code {
        0x01 => "the Apple TV refused the request".into(),
        0x02 => "wrong PIN — the Apple TV rejected the code".into(),
        0x03 => "too many attempts; the Apple TV is refusing new ones for a while".into(),
        0x04 => "the Apple TV will not pair with any more controllers".into(),
        0x05 => "too many wrong PINs — restart the Apple TV to try again".into(),
        0x06 => "the Apple TV is not accepting pairings right now".into(),
        0x07 => "the Apple TV is busy pairing with something else".into(),
        other => format!("the Apple TV refused pairing (code {other})"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_value_round_trips() {
        let items = vec![(STATE, vec![1]), (METHOD, vec![0])];
        assert_eq!(decode(&encode(&items)), items);
    }

    /// The one that matters. An SRP public key is 384 bytes, so it is always fragmented, and a
    /// reader that stops at the first entry gets 255 bytes that look like a key.
    #[test]
    fn a_long_value_is_fragmented_and_rejoined() {
        let key: Vec<u8> = (0..384).map(|i| (i % 251) as u8).collect();
        let wire = encode(&[(PUBLIC_KEY, key.clone())]);

        assert_eq!(wire[0], PUBLIC_KEY);
        assert_eq!(wire[1], 255, "the first fragment should be full");
        assert_eq!(wire[257], PUBLIC_KEY, "the second fragment repeats the type");
        assert_eq!(wire[258], (384 - 255) as u8);

        let back = decode(&wire);
        assert_eq!(back.len(), 1, "fragments must rejoin into one entry");
        assert_eq!(get(&back, PUBLIC_KEY), Some(key.as_slice()));
    }

    /// Two values of the same type that are *not* fragments of one another stay separate as long
    /// as something sits between them — which is what the HAP encoding relies on.
    #[test]
    fn separated_entries_of_one_type_stay_separate() {
        let wire = encode(&[(STATE, vec![1]), (METHOD, vec![0]), (STATE, vec![3])]);
        let back = decode(&wire);
        assert_eq!(back.len(), 3);
        assert_eq!(back[0], (STATE, vec![1]));
        assert_eq!(back[2], (STATE, vec![3]));
    }

    #[test]
    fn a_truncated_message_keeps_what_parsed() {
        let wire = encode(&[(SALT, vec![9; 16]), (PUBLIC_KEY, vec![1; 200])]);
        let back = decode(&wire[..30]);
        assert_eq!(get(&back, SALT), Some([9u8; 16].as_slice()));
    }

    #[test]
    fn an_error_becomes_something_a_person_can_act_on() {
        let wire = encode(&[(STATE, vec![4]), (ERROR, vec![0x02])]);
        assert!(error(&decode(&wire)).unwrap().contains("wrong PIN"));
        assert!(error(&decode(&encode(&[(STATE, vec![2])]))).is_none());
    }
}
