//! The HAP pairing handshake, which is what Companion runs under its own framing.
//!
//! Two procedures, and they are not alternatives — the first is run once with a PIN off the
//! television, the second on every connection afterwards:
//!
//! - **Pair Setup** (`M1`–`M6`): SRP-6a against the PIN, ending with each side holding the
//!   other's long-term Ed25519 public key. What comes out is [`Pairing`], stored as device
//!   properties.
//! - **Pair Verify** (`M1`–`M4`): X25519 exchange signed by those long-term keys, ending with
//!   the two ChaCha20-Poly1305 session keys the connection is encrypted with.
//!
//! # Why this is here and not in core
//!
//! Core has this handshake already, in `transport/hap.rs`, because HAP is a *link* — an ecobee,
//! a Nanoleaf panel and a door lock all speak it, and none should ship their own copy of SRP.
//! Companion is the opposite: exactly one manufacturer's boxes speak it, the framing around the
//! handshake is Apple's, and vendor knowledge is the driver's job. So the cost of a second copy
//! is accepted deliberately rather than by omission.
//!
//! # The parts that are easy to get subtly wrong
//!
//! - **SRP here is the specification's version, not the common one.** The `srp` crate says in
//!   its own source that its `M1` "doesn't follow the spec but apparently no one does". HAP
//!   does. So `u`, `M1` and `M2` are computed below against `PAD`ded values, and the crate is
//!   used only for the 3072-bit group and the modular arithmetic.
//! - **`K` is `H(S)`, not `S`.** Every HKDF here keys off the hash of the premaster secret.
//! - **Padding.** A big-endian integer drops its leading zero byte about one time in 256. Left
//!   unpadded, pairing works 255 times out of 256 and then fails for no visible reason.
//! - **Nonces are 8 bytes during pairing and 12 in the session.** ChaCha20-Poly1305 wants 12,
//!   so the pairing ones are the ASCII string left-padded with four zeros. Getting this
//!   backwards decrypts to nothing with no clue why.

use crate::opack;
use crate::tlv8;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::{Digest, Sha512};

/// What Pair Setup produces and Pair Verify consumes. Stored as device properties; only
/// `client_sk` is a secret the device does not already know, which is why it lives in a
/// `password` property.
#[derive(Debug, Clone, PartialEq)]
pub struct Pairing {
    /// The Apple TV's pairing identifier, as it sent it.
    pub device_id: Vec<u8>,
    /// Its long-term Ed25519 public key.
    pub device_ltpk: Vec<u8>,
    /// Ours — a UUID we invented at pairing time and must keep using.
    pub client_id: Vec<u8>,
    /// Our Ed25519 seed. Proves we are the controller it paired with.
    pub client_sk: [u8; 32],
}

fn sha512(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// HAP derives every key with HKDF-SHA512 to 32 bytes.
pub fn hkdf(salt: &[u8], info: &[u8], secret: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha512>::new(Some(salt), secret)
        .expand(info, &mut out)
        .expect("32 bytes is a valid HKDF length for SHA-512");
    out
}

/// Left-pad to the modulus width. See the note at the top about the one-in-256 failure.
fn pad(value: &BigUint, width: usize) -> Vec<u8> {
    let raw = value.to_bytes_be();
    let mut out = vec![0u8; width.saturating_sub(raw.len())];
    out.extend_from_slice(&raw);
    out
}

/// An 8-byte pairing nonce, in the 12-byte form ChaCha20-Poly1305 takes: four zeros, then the
/// ASCII. `PS-Msg05` and friends are 8 characters exactly, which is why they fit.
fn nonce_of(label: &[u8]) -> Nonce {
    let mut n = [0u8; 12];
    n[12 - label.len()..].copy_from_slice(label);
    *Nonce::from_slice(&n)
}

pub fn seal(key: &[u8; 32], label: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(&nonce_of(label), plain)
        .map_err(|_| "could not encrypt the pairing message".to_string())
}

pub fn open(key: &[u8; 32], label: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(&nonce_of(label), sealed)
        .map_err(|_| "could not decrypt the Apple TV's reply — wrong key or wrong PIN".to_string())
}

/// Encrypt or decrypt a *session* frame, whose nonce is a little-endian counter and whose
/// additional data is the frame header. Both directions have their own counter.
pub fn session_seal(
    key: &[u8; 32],
    counter: u64,
    header: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, String> {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            Nonce::from_slice(&n),
            Payload {
                msg: plain,
                aad: header,
            },
        )
        .map_err(|_| "could not encrypt a frame".to_string())
}

pub fn session_open(
    key: &[u8; 32],
    counter: u64,
    header: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            Nonce::from_slice(&n),
            Payload {
                msg: sealed,
                aad: header,
            },
        )
        .map_err(|_| "could not decrypt a frame — the session is out of step".to_string())
}

// ---------------------------------------------------------------------------------------
// Pair Setup
// ---------------------------------------------------------------------------------------

/// The client's half of Pair Setup, carried across the round trips.
pub struct Setup {
    a: BigUint,
    a_pub_padded: Vec<u8>,
    session_key: Vec<u8>,
    proof: Vec<u8>,
    pub client_seed: [u8; 32],
    pub client_id: Vec<u8>,
}

/// `M1` — ask to start. The Apple TV answers with a salt, a public value, and a PIN on screen.
pub fn setup_start() -> Vec<u8> {
    tlv8::encode(&[(tlv8::METHOD, vec![0]), (tlv8::STATE, vec![1])])
}

/// `M3` — having been given the salt and the device's public value, prove we know the PIN.
///
/// `seed` and `client_id` are passed in rather than generated here so that the caller owns
/// every source of randomness. A driver is re-entered fresh on each setup step and cannot hold
/// state between them; anything generated here would be a different value next time.
pub fn setup_prove(
    pin: &str,
    salt: &[u8],
    device_pub: &[u8],
    seed: [u8; 32],
    client_id: Vec<u8>,
) -> Result<(Setup, Vec<u8>), String> {
    let digits: String = pin.chars().filter(char::is_ascii_digit).collect();
    if digits.len() != 4 && digits.len() != 6 && digits.len() != 8 {
        return Err("the PIN on the Apple TV is 4 digits (or 6 or 8 on older ones)".into());
    }

    let group = &*srp::groups::G_3072;
    let width = group.n.to_bytes_be().len();
    let client = srp::client::SrpClient::<Sha512>::new(group);

    // `a` is a random exponent; the seed doubles as it, which is what pyatv does — the value
    // only has to be secret and unpredictable, and it is discarded after this exchange.
    let a = BigUint::from_bytes_be(&seed);
    let a_pub = client.compute_a_pub(&a);
    let b_pub = BigUint::from_bytes_be(device_pub);
    if &b_pub % &group.n == BigUint::default() {
        return Err("the Apple TV sent an invalid SRP public key".into());
    }

    let a_padded = pad(&a_pub, width);
    let b_padded = pad(&b_pub, width);
    let u = BigUint::from_bytes_be(&sha512(&[&a_padded, &b_padded]));
    let k = srp::utils::compute_k::<Sha512>(group);
    let identity =
        srp::client::SrpClient::<Sha512>::compute_identity_hash(b"Pair-Setup", digits.as_bytes());
    let x = srp::client::SrpClient::<Sha512>::compute_x(identity.as_slice(), salt);
    let premaster = client.compute_premaster_secret(&b_pub, &k, &x, &a, &u);

    // K = H(S). Everything downstream keys off this, not off S.
    let session_key = sha512(&[&premaster.to_bytes_be()]);

    // M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
    let h_n = sha512(&[&group.n.to_bytes_be()]);
    let h_g = sha512(&[&group.g.to_bytes_be()]);
    let xor: Vec<u8> = h_n.iter().zip(&h_g).map(|(l, r)| l ^ r).collect();
    let h_i = sha512(&[b"Pair-Setup"]);
    let proof = sha512(&[&xor, &h_i, salt, &a_padded, &b_padded, &session_key]);

    let tlv = tlv8::encode(&[
        (tlv8::STATE, vec![3]),
        (tlv8::PUBLIC_KEY, a_padded.clone()),
        (tlv8::PROOF, proof.clone()),
    ]);
    Ok((
        Setup {
            a,
            a_pub_padded: a_padded,
            session_key,
            proof,
            client_seed: seed,
            client_id,
        },
        tlv,
    ))
}

impl Setup {
    /// `M5` — check the device proved it knows the PIN too, then hand over our identity.
    ///
    /// The proof check is not a formality. Without it anything that could echo a salt would be
    /// accepted as an Apple TV, and the identity below would be handed to it.
    pub fn setup_exchange(&self, device_proof: &[u8], name: &str) -> Result<Vec<u8>, String> {
        let expect = sha512(&[&self.a_pub_padded, &self.proof, &self.session_key]);
        if device_proof != expect.as_slice() {
            return Err("the Apple TV's proof did not match — wrong PIN".into());
        }
        let _ = &self.a; // kept so the exponent is not dropped before the exchange completes

        let signing = ed25519_dalek::SigningKey::from_bytes(&self.client_seed);
        let client_ltpk = signing.verifying_key().to_bytes().to_vec();

        let controller_x = hkdf(
            b"Pair-Setup-Controller-Sign-Salt",
            b"Pair-Setup-Controller-Sign-Info",
            &self.session_key,
        );
        let mut to_sign = controller_x.to_vec();
        to_sign.extend_from_slice(&self.client_id);
        to_sign.extend_from_slice(&client_ltpk);
        let signature = {
            use ed25519_dalek::Signer;
            signing.sign(&to_sign).to_bytes().to_vec()
        };

        // Apple wants the controller's name here, as an OPACK blob rather than a plain string —
        // this is the entry that appears in Settings > Remotes and Devices.
        let name_blob = opack::pack(&opack::dict([("name", opack::s(name))]));

        let inner = tlv8::encode(&[
            (tlv8::IDENTIFIER, self.client_id.clone()),
            (tlv8::PUBLIC_KEY, client_ltpk),
            (tlv8::SIGNATURE, signature),
            (tlv8::NAME, name_blob),
        ]);

        let key = hkdf(
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
            &self.session_key,
        );
        let sealed = seal(&key, b"PS-Msg05", &inner)?;
        Ok(tlv8::encode(&[
            (tlv8::STATE, vec![5]),
            (tlv8::ENCRYPTED_DATA, sealed),
        ]))
    }

    /// `M6` — open the device's identity and keep it. This is the pairing.
    pub fn setup_finish(&self, encrypted: &[u8]) -> Result<Pairing, String> {
        let key = hkdf(
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
            &self.session_key,
        );
        let plain = open(&key, b"PS-Msg06", encrypted)?;
        let tlv = tlv8::decode(&plain);
        Ok(Pairing {
            device_id: tlv8::get(&tlv, tlv8::IDENTIFIER)
                .ok_or("the Apple TV sent no identifier")?
                .to_vec(),
            device_ltpk: tlv8::get(&tlv, tlv8::PUBLIC_KEY)
                .ok_or("the Apple TV sent no public key")?
                .to_vec(),
            client_id: self.client_id.clone(),
            client_sk: self.client_seed,
        })
    }
}

// ---------------------------------------------------------------------------------------
// Pair Verify
// ---------------------------------------------------------------------------------------

/// Companion's session keys are derived with an empty salt and these two info strings. The
/// names are from the device's point of view, so ours is the *client* one.
pub const SESSION_SALT: &[u8] = b"";
pub const WRITE_INFO: &[u8] = b"ClientEncrypt-main";
pub const READ_INFO: &[u8] = b"ServerEncrypt-main";

pub struct Verify {
    secret: x25519_dalek::StaticSecret,
    public: [u8; 32],
}

/// `M1` — offer an ephemeral X25519 public key.
pub fn verify_start(seed: [u8; 32]) -> (Verify, Vec<u8>) {
    let secret = x25519_dalek::StaticSecret::from(seed);
    let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    let tlv = tlv8::encode(&[(tlv8::STATE, vec![1]), (tlv8::PUBLIC_KEY, public.to_vec())]);
    (Verify { secret, public }, tlv)
}

impl Verify {
    /// `M3` — check the device signed the exchange with the key we paired with, and sign back.
    pub fn verify_prove(
        &self,
        pairing: &Pairing,
        device_pub: &[u8],
        encrypted: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32], [u8; 32]), String> {
        let mut theirs = [0u8; 32];
        if device_pub.len() != 32 {
            return Err("the Apple TV sent a malformed public key".into());
        }
        theirs.copy_from_slice(device_pub);
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(theirs));
        let shared = shared.as_bytes();

        let key = hkdf(
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
            shared,
        );
        let plain = open(&key, b"PV-Msg02", encrypted)?;
        let tlv = tlv8::decode(&plain);
        let identifier = tlv8::get(&tlv, tlv8::IDENTIFIER).ok_or("no identifier in the reply")?;
        let signature = tlv8::get(&tlv, tlv8::SIGNATURE).ok_or("no signature in the reply")?;

        if identifier != pairing.device_id.as_slice() {
            return Err("this is a different Apple TV than the one that was paired".into());
        }

        // It signs (its ephemeral key | its id | ours). Verifying with the long-term key we
        // kept at pairing is the whole point: it is what makes this the same device.
        let mut signed = Vec::new();
        signed.extend_from_slice(device_pub);
        signed.extend_from_slice(identifier);
        signed.extend_from_slice(&self.public);

        let ltpk: [u8; 32] = pairing
            .device_ltpk
            .as_slice()
            .try_into()
            .map_err(|_| "the stored key for this Apple TV is malformed".to_string())?;
        let sig: [u8; 64] = signature
            .try_into()
            .map_err(|_| "the Apple TV sent a malformed signature".to_string())?;
        {
            use ed25519_dalek::Verifier;
            ed25519_dalek::VerifyingKey::from_bytes(&ltpk)
                .map_err(|_| "the stored key for this Apple TV is not a valid key".to_string())?
                .verify(&signed, &ed25519_dalek::Signature::from_bytes(&sig))
                .map_err(|_| {
                    "the Apple TV's signature did not check out — it may have been reset".to_string()
                })?;
        }

        // Sign the mirror image back, so it knows we still hold the key it paired with.
        let signing = ed25519_dalek::SigningKey::from_bytes(&pairing.client_sk);
        let mut ours = Vec::new();
        ours.extend_from_slice(&self.public);
        ours.extend_from_slice(&pairing.client_id);
        ours.extend_from_slice(device_pub);
        let signature = {
            use ed25519_dalek::Signer;
            signing.sign(&ours).to_bytes().to_vec()
        };

        let inner = tlv8::encode(&[
            (tlv8::IDENTIFIER, pairing.client_id.clone()),
            (tlv8::SIGNATURE, signature),
        ]);
        let sealed = seal(&key, b"PV-Msg03", &inner)?;
        let tlv = tlv8::encode(&[
            (tlv8::STATE, vec![3]),
            (tlv8::ENCRYPTED_DATA, sealed),
        ]);

        let write = hkdf(SESSION_SALT, WRITE_INFO, shared);
        let read = hkdf(SESSION_SALT, READ_INFO, shared);
        Ok((tlv, write, read))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Padding is the one-in-256 bug. A value that happens to be short must still occupy the
    /// modulus width, or `u`, `M1` and `M2` are all computed over different bytes than the
    /// device computed them over — and pairing fails with nothing to point at.
    #[test]
    fn padding_keeps_a_short_value_at_the_full_width() {
        let small = BigUint::from(1u8);
        assert_eq!(pad(&small, 384).len(), 384);
        assert_eq!(pad(&small, 384)[383], 1);
        assert_eq!(pad(&small, 384)[0], 0);
        // Already full width: unchanged, not truncated or re-padded.
        let big = BigUint::from_bytes_be(&[0xFFu8; 384]);
        assert_eq!(pad(&big, 384), vec![0xFFu8; 384]);
    }

    /// Pairing nonces are 8 ASCII bytes in a 12-byte field, right-aligned. Left-aligning them
    /// decrypts to nothing, with no indication of which end was wrong.
    #[test]
    fn a_pairing_nonce_is_right_aligned_in_twelve_bytes() {
        let n = nonce_of(b"PS-Msg05");
        assert_eq!(&n.as_slice()[..4], &[0, 0, 0, 0]);
        assert_eq!(&n.as_slice()[4..], b"PS-Msg05");
    }

    #[test]
    fn a_sealed_pairing_message_opens_again() {
        let key = [7u8; 32];
        let sealed = seal(&key, b"PS-Msg05", b"hello").unwrap();
        assert_eq!(open(&key, b"PS-Msg05", &sealed).unwrap(), b"hello");
        // Wrong label, wrong key: both refused rather than returning rubbish.
        assert!(open(&key, b"PS-Msg06", &sealed).is_err());
        assert!(open(&[8u8; 32], b"PS-Msg05", &sealed).is_err());
    }

    /// A session frame authenticates its header as additional data, so a frame whose length or
    /// type was altered in flight fails to open rather than being decrypted as something else.
    #[test]
    fn a_session_frame_is_bound_to_its_header() {
        let key = [3u8; 32];
        let header = [0x08, 0, 0, 0x10];
        let sealed = session_seal(&key, 0, &header, b"payload").unwrap();
        assert_eq!(session_open(&key, 0, &header, &sealed).unwrap(), b"payload");

        let tampered = [0x07, 0, 0, 0x10];
        assert!(
            session_open(&key, 0, &tampered, &sealed).is_err(),
            "a changed header must invalidate the frame"
        );
        assert!(
            session_open(&key, 1, &header, &sealed).is_err(),
            "the counter is part of the nonce, so a replayed frame does not open twice"
        );
    }

    /// The counter is little-endian in the last eight bytes of a twelve-byte nonce. A big-endian
    /// counter agrees with the device for exactly one frame — number zero — and then diverges,
    /// which reads as a connection that works once and then dies.
    #[test]
    fn the_session_counter_advances_the_nonce() {
        let key = [5u8; 32];
        let header = [0x08, 0, 0, 4];
        let first = session_seal(&key, 0, &header, b"a").unwrap();
        let second = session_seal(&key, 1, &header, b"a").unwrap();
        assert_ne!(first, second, "the counter has to reach the nonce");
        assert!(session_open(&key, 1, &header, &second).is_ok());
    }

    /// A PIN with the dashes people read off the screen, and one that is not a PIN at all.
    #[test]
    fn the_pin_is_checked_before_any_crypto_runs() {
        let err = match setup_prove("12", &[0; 16], &[1; 384], [0u8; 32], b"id".to_vec()) {
            Err(e) => e,
            Ok(_) => panic!("two digits is not a PIN"),
        };
        assert!(err.contains("PIN"), "{err}");

        // Four digits is what tvOS shows now; dashes and spaces are stripped rather than
        // refused, because that is how it is printed.
        assert!(setup_prove("1234", &[0; 16], &[1; 384], [9u8; 32], b"id".to_vec()).is_ok());
        assert!(setup_prove("123-45-678", &[0; 16], &[1; 384], [9u8; 32], b"id".to_vec()).is_ok());
    }

    /// Verify refuses a device that is not the one that was paired, before trusting anything
    /// it said. A reset Apple TV on the same address is the real case.
    #[test]
    fn verify_refuses_a_different_device() {
        let pairing = Pairing {
            device_id: b"the-one-we-paired".to_vec(),
            device_ltpk: vec![0u8; 32],
            client_id: b"us".to_vec(),
            client_sk: [1u8; 32],
        };
        let (verify, _) = verify_start([2u8; 32]);

        // Encrypt a reply claiming to be somebody else, using the key the exchange would derive.
        let secret = x25519_dalek::StaticSecret::from([4u8; 32]);
        let their_pub = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(verify.public));
        let key = hkdf(
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
            shared.as_bytes(),
        );
        let inner = tlv8::encode(&[
            (tlv8::IDENTIFIER, b"a-different-apple-tv".to_vec()),
            (tlv8::SIGNATURE, vec![0u8; 64]),
        ]);
        let sealed = seal(&key, b"PV-Msg02", &inner).unwrap();

        let err = verify
            .verify_prove(&pairing, &their_pub, &sealed)
            .expect_err("a different device must be refused");
        assert!(err.contains("different Apple TV"), "{err}");
    }
}
