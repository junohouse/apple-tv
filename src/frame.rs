//! Companion framing: one byte of type, three of big-endian length, then the payload.
//!
//! ```text
//!   +------+----------------+---------------------------+
//!   | type | length (24-bit)|  payload                  |
//!   +------+----------------+---------------------------+
//! ```
//!
//! Once the session is up the payload is ChaCha20-Poly1305, and the **header is the additional
//! data** — so the four bytes above are authenticated even though they are sent in clear. The
//! declared length then covers the ciphertext *including* its 16-byte tag, which is the detail
//! that decides whether a frame ever reassembles: length it as the plaintext and every frame
//! after the first is cut in the wrong place.
//!
//! Core hands this driver whatever bytes arrived in a window, not whole messages — it cannot
//! know where one ends. So [`Framer`] holds the leftovers between calls.

use crate::srp;

pub const PS_START: u8 = 0x03;
pub const PS_NEXT: u8 = 0x04;
pub const PV_START: u8 = 0x05;
pub const PV_NEXT: u8 = 0x06;
pub const E_OPACK: u8 = 0x08;

const HEADER: usize = 4;
const TAG: usize = 16;

/// Wrap a payload for the wire, encrypting if the session is up.
pub fn encode(
    kind: u8,
    payload: &[u8],
    key: Option<&[u8; 32]>,
    counter: u64,
) -> Result<Vec<u8>, String> {
    // The length counts the tag, because that is what will be on the wire. Empty payloads are
    // sent as-is: there is nothing to authenticate and the device does not expect a tag.
    let len = match key {
        Some(_) if !payload.is_empty() => payload.len() + TAG,
        _ => payload.len(),
    };
    if len > 0xFF_FFFF {
        return Err("frame too large for a 24-bit length".into());
    }
    let mut header = vec![kind];
    header.extend_from_slice(&(len as u32).to_be_bytes()[1..]);

    let body = match key {
        Some(k) if !payload.is_empty() => srp::session_seal(k, counter, &header, payload)?,
        _ => payload.to_vec(),
    };
    let mut out = header;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Accumulates bytes and yields whole frames.
#[derive(Default)]
pub struct Framer {
    buffer: Vec<u8>,
}

impl Framer {
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next whole frame, decrypted if a key is given. `None` means what has arrived so far
    /// is not yet a frame — which is normal, not an error.
    ///
    /// `counter` is only consumed when a frame actually comes out, so a partial read does not
    /// advance the sequence and desynchronise every frame after it.
    pub fn next(&mut self, key: Option<&[u8; 32]>, counter: u64) -> Option<Result<(u8, Vec<u8>), String>> {
        if self.buffer.len() < HEADER {
            return None;
        }
        let kind = self.buffer[0];
        let len = u32::from_be_bytes([0, self.buffer[1], self.buffer[2], self.buffer[3]]) as usize;
        if self.buffer.len() < HEADER + len {
            return None;
        }
        let header: Vec<u8> = self.buffer[..HEADER].to_vec();
        let body: Vec<u8> = self.buffer[HEADER..HEADER + len].to_vec();
        self.buffer.drain(..HEADER + len);

        let payload = match key {
            Some(k) if !body.is_empty() => match srp::session_open(k, counter, &header, &body) {
                Ok(p) => p,
                Err(e) => return Some(Err(e)),
            },
            _ => body,
        };
        Some(Ok((kind, payload)))
    }

    /// Whether anything is half-received. Used to decide there is nothing more to read rather
    /// than to report a problem — a frame split across two reads is ordinary.
    pub fn pending(&self) -> bool {
        !self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_frame_round_trips() {
        let wire = encode(E_OPACK, b"hello", None, 0).unwrap();
        assert_eq!(wire[0], E_OPACK);
        assert_eq!(&wire[1..4], &[0, 0, 5]);

        let mut f = Framer::default();
        f.feed(&wire);
        let (kind, payload) = f.next(None, 0).unwrap().unwrap();
        assert_eq!(kind, E_OPACK);
        assert_eq!(payload, b"hello");
        assert!(f.next(None, 0).is_none(), "nothing left");
    }

    /// The length has to count the auth tag. Length it as plaintext and the reader stops 16
    /// bytes early, then reads the tail of one frame as the header of the next — so the failure
    /// is not "one bad frame", it is every frame from there on.
    #[test]
    fn an_encrypted_frame_declares_the_length_including_its_tag() {
        let key = [4u8; 32];
        let wire = encode(E_OPACK, b"hello", Some(&key), 0).unwrap();
        let declared = u32::from_be_bytes([0, wire[1], wire[2], wire[3]]) as usize;
        assert_eq!(declared, 5 + 16);
        assert_eq!(wire.len(), 4 + declared);

        let mut f = Framer::default();
        f.feed(&wire);
        assert_eq!(f.next(Some(&key), 0).unwrap().unwrap().1, b"hello");
    }

    /// Core returns whatever arrived in a window, so a frame arriving in pieces is the normal
    /// case rather than an edge one.
    #[test]
    fn a_frame_split_across_reads_reassembles() {
        let key = [9u8; 32];
        let wire = encode(E_OPACK, b"a longer payload than one read", Some(&key), 3).unwrap();

        let mut f = Framer::default();
        for chunk in wire.chunks(7) {
            f.feed(chunk);
        }
        let (_, payload) = f.next(Some(&key), 3).unwrap().unwrap();
        assert_eq!(payload, b"a longer payload than one read");
    }

    /// A partial frame must not consume the counter, or every frame after it decrypts against
    /// the wrong nonce.
    #[test]
    fn a_partial_frame_yields_nothing_and_leaves_the_buffer_alone() {
        let key = [1u8; 32];
        let wire = encode(E_OPACK, b"payload", Some(&key), 0).unwrap();

        let mut f = Framer::default();
        f.feed(&wire[..6]);
        assert!(f.next(Some(&key), 0).is_none());
        assert!(f.pending(), "the partial frame is still held");

        f.feed(&wire[6..]);
        assert_eq!(f.next(Some(&key), 0).unwrap().unwrap().1, b"payload");
        assert!(!f.pending());
    }

    /// Two frames in one read, which is what happens when the device answers a request and
    /// pushes an event in the same breath.
    #[test]
    fn two_frames_in_one_read_come_out_separately() {
        let mut wire = encode(PV_START, b"one", None, 0).unwrap();
        wire.extend(encode(E_OPACK, b"two", None, 0).unwrap());

        let mut f = Framer::default();
        f.feed(&wire);
        assert_eq!(f.next(None, 0).unwrap().unwrap(), (PV_START, b"one".to_vec()));
        assert_eq!(f.next(None, 0).unwrap().unwrap(), (E_OPACK, b"two".to_vec()));
        assert!(f.next(None, 0).is_none());
    }

    /// An empty payload carries no tag in either direction — sending one would make the device
    /// read 16 bytes of a frame that is not there.
    #[test]
    fn an_empty_payload_is_not_padded_with_a_tag() {
        let key = [2u8; 32];
        let wire = encode(E_OPACK, b"", Some(&key), 0).unwrap();
        assert_eq!(wire.len(), 4);
        assert_eq!(&wire[1..4], &[0, 0, 0]);
    }
}
