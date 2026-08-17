//! Apple TV, over the Companion link it answers on — or over IR, which is a different driver
//! in the same package.
//!
//! ```text
//!   _companion-link._tcp   mDNS, and the SRV record carries the port. It is not fixed.
//!   PS_Start / PS_Next     Pair Setup, once, against a PIN on the television
//!   PV_Start / PV_Next     Pair Verify, on every connection after that
//!   E_OPACK                everything else, inside a ChaCha20-Poly1305 session
//! ```
//!
//! # "Play Severance in the den"
//!
//! The reason this exists rather than an IR blaster. `_launchApp` takes a bundle id **or a
//! URL**, so a title resolves to a link and the television goes straight to it. Nothing else in
//! this class of hardware does that — the market-leading Apple TV integration is a d-pad and a
//! play button — and the whole path is already in the contract: `launch_app` has taken
//! `content_id` since the Roku driver, and `has_deep_link` is what says this box honours it.
//!
//! Which links still work is [`links`]' problem, and it is a table because it rots.
//!
//! # What is not here
//!
//! Now-playing metadata and artwork. Those live in MRP, which since tvOS 15 is only reachable
//! tunnelled inside AirPlay 2 — a second protocol stack for information nobody has asked this
//! driver for yet. `has_metadata` is therefore not declared, rather than declared and empty.

pub mod frame;
pub mod links;
pub mod opack;
pub mod srp;
pub mod tlv8;

use driver_sdk::Value;
use driver_sdk::*;
use opack::Val;

/// The only proxy. An Apple TV is a *source* — it has no screen and no inputs of its own. It
/// does carry volume, over HDMI-CEC to whatever it is plugged into, which is why
/// `has_up_down_volume` is declared and `has_discrete_volume` is not: it can nudge, not set.
const MEDIA: LocalId = 1;

#[derive(Default)]
pub struct AppleTv;

/// `_hidC` button numbers, from the reverse-engineered Companion table.
mod hid {
    pub const UP: u64 = 1;
    pub const DOWN: u64 = 2;
    pub const LEFT: u64 = 3;
    pub const RIGHT: u64 = 4;
    pub const MENU: u64 = 5;
    pub const SELECT: u64 = 6;
    pub const HOME: u64 = 7;
    pub const VOLUME_UP: u64 = 8;
    pub const VOLUME_DOWN: u64 = 9;
    pub const PLAY_PAUSE: u64 = 14;
}

/// A pairing frame's payload: the TLV, whatever flags the step needs, and a transaction id.
///
/// `_x` is on *every* OPACK frame, auth ones included — the reference adds it in the one place
/// all sends go through, which is easy to miss when the pairing frames are built by hand. A
/// frame without it is a frame the device cannot match a reply to.
fn pairing_frame(tlv: Vec<u8>, flag: (&str, u64), xid: u64) -> Val {
    opack::dict([
        ("_pd", Val::Data(tlv)),
        (flag.0, Val::Int(flag.1)),
        ("_x", Val::Int(xid)),
    ])
}

/// The `hold` keys this box actually has.
///
/// Narrower than the contract's list, and deliberately so — the contract cannot gate `what` per
/// key, so refusing here is the only place the truth gets told. tvOS has no scan keys at all:
/// scrubbing is a hold of left or right, which is why `scan_forward` is absent rather than
/// aliased to something that would move the wrong way.
fn holdable(what: &str) -> Option<u64> {
    Some(match what {
        "volume_up" => hid::VOLUME_UP,
        "volume_down" => hid::VOLUME_DOWN,
        "up" => hid::UP,
        "down" => hid::DOWN,
        "left" => hid::LEFT,
        "right" => hid::RIGHT,
        _ => return None,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn random32() -> [u8; 32] {
    let mut out = [0u8; 32];
    // The controller has an OS RNG; a driver with no entropy is one that generates the same
    // pairing key every time, which would be worse than failing to pair at all.
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut out);
    out
}

impl AppleTv {
    /// The pairing this device was set up with, out of its properties.
    fn pairing(inst: &Instance) -> Option<srp::Pairing> {
        Some(srp::Pairing {
            device_id: unhex(inst.property("Device id").as_str()?)?,
            device_ltpk: unhex(inst.property("Device key").as_str()?)?,
            client_id: unhex(inst.property("Controller id").as_str()?)?,
            client_sk: unhex(inst.property("Controller key").as_str()?)?
                .try_into()
                .ok()?,
        })
    }

    /// Send an `E_OPACK` request inside the session, if there is one.
    fn send(inst: &mut Instance, message: Val) -> Vec<HostCall> {
        let Some(keys) = Session::load(inst) else {
            // Not verified yet. Dropping is right rather than queueing: the next thing that
            // happens is a reconnect, and a command from thirty seconds ago is not what anybody
            // still wants pressed.
            return vec![HostCall::warn(
                "apple-tv: not connected yet — the session is still coming up",
            )];
        };
        let payload = opack::pack(&message);
        match frame::encode(frame::E_OPACK, &payload, Some(&keys.write), keys.out) {
            Ok(bytes) => {
                Session::advance_out(inst);
                vec![HostCall::Tx {
                    control: 0,
                    data: bytes,
                }]
            }
            Err(e) => vec![HostCall::warn(format!("apple-tv: {e}"))],
        }
    }

    /// One `E_OPACK` request envelope. `_x` is a transaction id the reply echoes.
    fn request(inst: &mut Instance, name: &str, content: Val) -> Vec<HostCall> {
        let xid = inst
            .scratch
            .get("xid")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            + 1;
        inst.scratch.insert("xid".into(), json!(xid));
        Self::send(
            inst,
            opack::dict([
                ("_i", opack::s(name)),
                ("_t", Val::Int(2)),
                ("_x", Val::Int(xid)),
                ("_c", content),
            ]),
        )
    }

    /// Press a button and let it go again — a tap.
    ///
    /// tvOS wants both halves. A press with no release leaves the key down, which on an arrow
    /// scrolls until something else stops it; that is a real gesture, but it is [`Self::hold`]
    /// and it has to be asked for.
    fn button(inst: &mut Instance, code: u64) -> Vec<HostCall> {
        let mut out = Self::press(inst, code);
        out.extend(Self::lift(inst, code));
        out
    }

    fn press(inst: &mut Instance, code: u64) -> Vec<HostCall> {
        Self::request(
            inst,
            "_hidC",
            opack::dict([("_hBtS", Val::Int(1)), ("_hidC", Val::Int(code))]),
        )
    }

    fn lift(inst: &mut Instance, code: u64) -> Vec<HostCall> {
        Self::request(
            inst,
            "_hidC",
            opack::dict([("_hBtS", Val::Int(2)), ("_hidC", Val::Int(code))]),
        )
    }

    /// The key a `hold` is holding, so `release` knows what to let go of.
    ///
    /// One at a time, which is what the contract says and what a hand does. A second `hold`
    /// releases the first rather than stacking: two keys held at once on a remote that has one
    /// finger on it is a state nothing can get out of.
    fn held(inst: &Instance) -> Option<u64> {
        inst.scratch.get("held").and_then(Value::as_u64)
    }
}

/// The session keys and counters, kept on the instance because a driver is re-entered fresh.
struct Session {
    write: [u8; 32],
    read: [u8; 32],
    out: u64,
    inn: u64,
}

impl Session {
    fn load(inst: &Instance) -> Option<Session> {
        Some(Session {
            write: unhex(inst.scratch.get("write")?.as_str()?)?.try_into().ok()?,
            read: unhex(inst.scratch.get("read")?.as_str()?)?.try_into().ok()?,
            out: inst.scratch.get("out").and_then(Value::as_u64).unwrap_or(0),
            inn: inst.scratch.get("in").and_then(Value::as_u64).unwrap_or(0),
        })
    }

    fn store(inst: &mut Instance, write: [u8; 32], read: [u8; 32]) {
        inst.scratch.insert("write".into(), json!(hex(&write)));
        inst.scratch.insert("read".into(), json!(hex(&read)));
        inst.scratch.insert("out".into(), json!(0));
        inst.scratch.insert("in".into(), json!(0));
    }

    /// Both counters advance per frame and independently. Advancing the wrong one, or advancing
    /// on a frame that did not go out, desynchronises everything after it.
    fn advance_out(inst: &mut Instance) {
        let n = inst.scratch.get("out").and_then(Value::as_u64).unwrap_or(0);
        inst.scratch.insert("out".into(), json!(n + 1));
    }

    fn advance_in(inst: &mut Instance) {
        let n = inst.scratch.get("in").and_then(Value::as_u64).unwrap_or(0);
        inst.scratch.insert("in".into(), json!(n + 1));
    }

    /// Forget the session. Also forgets a key that was being held — the release for it can no
    /// longer be sent down a socket that is gone, and tvOS drops HID state with the session, so
    /// remembering it would only mean the *next* connection sent a release for a key nothing is
    /// holding.
    fn clear(inst: &mut Instance) {
        for k in ["write", "read", "out", "in", "verify_seed", "buffer", "held"] {
            inst.scratch.remove(k);
        }
    }
}

impl DriverModule for AppleTv {
    fn discover(&self, _driver_id: &str, state: &Value, input: &Args) -> (SetupStep, Value) {
        self.flow(state, input)
    }

    fn setup(&self, _driver_id: &str, state: &Value, input: &Args) -> (SetupStep, Value) {
        self.flow(state, input)
    }

    // -----------------------------------------------------------------------------------
    // Connection
    // -----------------------------------------------------------------------------------

    /// Open the session by running Pair Verify. Nothing else can be sent until it finishes.
    fn on_bind(&self, inst: &mut Instance) -> Vec<HostCall> {
        Session::clear(inst);
        if Self::pairing(inst).is_none() {
            return vec![HostCall::warn(
                "apple-tv: this device has not been paired — run its setup again",
            )];
        }

        let seed = random32();
        inst.scratch.insert("verify_seed".into(), json!(hex(&seed)));
        let (_, tlv) = srp::verify_start(seed);

        let payload = opack::pack(&pairing_frame(tlv, ("_auTy", 4), 1));
        match frame::encode(frame::PV_START, &payload, None, 0) {
            Ok(bytes) => vec![HostCall::Tx {
                control: 0,
                data: bytes,
            }],
            Err(e) => vec![HostCall::warn(format!("apple-tv: {e}"))],
        }
    }

    fn on_event(
        &self,
        inst: &mut Instance,
        _control: LocalId,
        note: &str,
        args: &Args,
    ) -> Vec<HostCall> {
        if note != "rx" {
            return Vec::new();
        }
        // Core hands over whatever arrived in a window. `bytes` rather than `data` because this
        // transport declares `binary` — see the manifest.
        let Some(chunk) = args.get("bytes").and_then(Value::as_array) else {
            return Vec::new();
        };
        let chunk: Vec<u8> = chunk
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u8))
            .collect();

        let mut framer = frame::Framer::default();
        if let Some(held) = inst.scratch.get("buffer").and_then(Value::as_str)
            && let Some(bytes) = unhex(held)
        {
            framer.feed(&bytes);
        }
        framer.feed(&chunk);

        let mut out = Vec::new();
        loop {
            // The key and counter are re-read each time round: a frame may be the one that
            // establishes the session, and the frame after it is already encrypted.
            let session = Session::load(inst);
            let key = session.as_ref().map(|s| s.read);
            let counter = session.as_ref().map(|s| s.inn).unwrap_or(0);
            let Some(next) = framer.next(key.as_ref(), counter) else {
                break;
            };
            match next {
                Ok((kind, payload)) => {
                    if key.is_some() && !payload.is_empty() {
                        Session::advance_in(inst);
                    }
                    out.extend(self.on_frame(inst, kind, &payload));
                }
                Err(e) => {
                    // A frame that will not open means the session is out of step, and every
                    // frame after it is unreadable too. Tear it down so the next bind rebuilds.
                    Session::clear(inst);
                    out.push(HostCall::warn(format!("apple-tv: {e}")));
                    break;
                }
            }
        }

        // Whatever is half-received waits for the next read. A driver cannot hold a `Framer`
        // between events, so the tail lives on the instance.
        let leftover = framer.take();
        inst.scratch.insert("buffer".into(), json!(hex(&leftover)));
        out
    }

    // -----------------------------------------------------------------------------------
    // Commands
    // -----------------------------------------------------------------------------------

    fn on_command(
        &self,
        inst: &mut Instance,
        _proxy: LocalId,
        cmd: &str,
        args: &Args,
    ) -> Vec<HostCall> {
        match cmd {
            "launch_app" => {
                let Some(app) = args.get("app").and_then(Value::as_str) else {
                    return vec![HostCall::warn("apple-tv: launch_app needs an app")];
                };
                // What the device itself reported for this name, when it reported anything.
                let installed = inst
                    .scratch
                    .get("bundles")
                    .and_then(Value::as_object)
                    .and_then(|m| {
                        m.iter()
                            .find(|(name, _)| {
                                name.to_lowercase().starts_with(&app.to_lowercase())
                                    || app.to_lowercase().starts_with(&name.to_lowercase())
                            })
                            .and_then(|(_, id)| id.as_str())
                            .map(str::to_string)
                    });

                // What the shared catalog says this platform calls the app, when core knew one.
                // Used only where the device itself said nothing — see `links::resolve`.
                let launch = links::resolve(
                    app,
                    installed.as_deref(),
                    args.get("launch_id").and_then(Value::as_str),
                    args.get("content_id").and_then(Value::as_str),
                    args.get("content_kind").and_then(Value::as_str),
                );

                let (key, target, note) = match launch {
                    links::Launch::DeepLink(url) => ("_urlS", url, None),
                    links::Launch::AppOnly { target, why } => ("_bundleID", target, why),
                };

                let mut out = Self::request(
                    inst,
                    "_launchApp",
                    opack::dict([(key, opack::s(&target))]),
                );
                let mut a = Args::new();
                a.insert("app".into(), json!(app));
                out.push(HostCall::notify(MEDIA, "app_changed", a));
                // Said out loud when a title could not be honoured, because the alternative is
                // reporting success for something that visibly did not happen.
                if let Some(note) = note {
                    out.push(HostCall::Log {
                        level: "info".into(),
                        msg: note,
                    });
                }
                out
            }

            "dpad" => {
                let Some(k) = args.get("key").and_then(Value::as_str) else {
                    return vec![HostCall::warn("apple-tv: dpad needs a key")];
                };
                let code = match k {
                    "up" => hid::UP,
                    "down" => hid::DOWN,
                    "left" => hid::LEFT,
                    "right" => hid::RIGHT,
                    "select" => hid::SELECT,
                    // tvOS has no separate Back: Menu is the way out of anything.
                    "back" | "menu" => hid::MENU,
                    "home" => hid::HOME,
                    // No Info button either. Holding Select is what opens the context menu, and
                    // that is a hold rather than a tap, so it is not this command.
                    other => {
                        return vec![HostCall::warn(format!(
                            "apple-tv: tvOS has no `{other}` key"
                        ))];
                    }
                };
                Self::button(inst, code)
            }

            // One toggle, not two keys, which is all tvOS exposes. Reporting the state we asked
            // for would be a guess — nothing here knows what was playing.
            "play" | "pause" => Self::button(inst, hid::PLAY_PAUSE),
            "stop" => Self::button(inst, hid::MENU),

            "volume_up" => Self::button(inst, hid::VOLUME_UP),
            "volume_down" => Self::button(inst, hid::VOLUME_DOWN),

            // A ramp: press and do not let go. The device repeats on its own for as long as the
            // key is down, which is why nothing here loops.
            "hold" => {
                let Some(what) = args.get("what").and_then(Value::as_str) else {
                    return vec![HostCall::warn("apple-tv: hold needs a key")];
                };
                let Some(code) = holdable(what) else {
                    // tvOS has no scan keys — scrubbing is a hold of left or right — so asking
                    // for one is a mistake worth naming rather than a silent no-op.
                    return vec![HostCall::warn(format!(
                        "apple-tv: `{what}` cannot be held; try up, down, left, right, \
                         volume_up or volume_down"
                    ))];
                };
                // A second hold lets go of the first. Stacking them would leave a key down that
                // nothing has a name for any more.
                let mut out = match Self::held(inst) {
                    Some(prev) if prev != code => Self::lift(inst, prev),
                    _ => Vec::new(),
                };
                inst.scratch.insert("held".into(), json!(code));
                out.extend(Self::press(inst, code));
                out
            }

            "release" => match Self::held(inst) {
                Some(code) => {
                    inst.scratch.remove("held");
                    Self::lift(inst, code)
                }
                // Releasing nothing is not an error. A rule that brackets a hold will send this
                // after a reconnect cleared the state, and warning about it would put a line in
                // the log every time somebody let go of a button.
                None => Vec::new(),
            },

            "search" => Self::button(inst, hid::HOME),

            other => vec![HostCall::warn(format!("apple-tv: unhandled `{other}`"))],
        }
    }
}

impl AppleTv {
    /// One decoded frame.
    fn on_frame(&self, inst: &mut Instance, kind: u8, payload: &[u8]) -> Vec<HostCall> {
        let Ok(message) = opack::unpack(payload) else {
            return Vec::new();
        };

        match kind {
            // Pair Verify's reply: check the signature, derive the session keys, open up.
            frame::PV_START | frame::PV_NEXT => {
                let Some(pd) = message.get("_pd").and_then(Val::as_data) else {
                    return Vec::new();
                };
                let tlv = tlv8::decode(pd);
                if let Some(e) = tlv8::error(&tlv) {
                    Session::clear(inst);
                    return vec![HostCall::warn(format!("apple-tv: {e}"))];
                }
                // Only the M2 reply carries both; M4 carries neither and is the end of it.
                let (Some(their_pub), Some(encrypted)) = (
                    tlv8::get(&tlv, tlv8::PUBLIC_KEY),
                    tlv8::get(&tlv, tlv8::ENCRYPTED_DATA),
                ) else {
                    return Vec::new();
                };

                let Some(pairing) = Self::pairing(inst) else {
                    return Vec::new();
                };
                let Some(seed) = inst
                    .scratch
                    .get("verify_seed")
                    .and_then(Value::as_str)
                    .and_then(unhex)
                    .and_then(|v| <[u8; 32]>::try_from(v).ok())
                else {
                    return Vec::new();
                };
                let (verify, _) = srp::verify_start(seed);

                let (tlv, write, read) =
                    match verify.verify_prove(&pairing, their_pub, encrypted) {
                        Ok(v) => v,
                        Err(e) => {
                            Session::clear(inst);
                            return vec![HostCall::warn(format!("apple-tv: {e}"))];
                        }
                    };

                let payload = opack::pack(&pairing_frame(tlv, ("_auTy", 4), 2));
                let Ok(bytes) = frame::encode(frame::PV_NEXT, &payload, None, 0) else {
                    return Vec::new();
                };

                // The keys apply from the *next* frame, so store them after building this one.
                Session::store(inst, write, read);

                let mut out = vec![HostCall::Tx {
                    control: 0,
                    data: bytes,
                }];

                // What the remote widget does on connect, in the same order. `_systemInfo`
                // first or tvOS answers nothing else.
                out.extend(Self::request(
                    inst,
                    "_systemInfo",
                    opack::dict([
                        ("_bf", Val::Int(0)),
                        ("_cf", Val::Int(512)),
                        ("_clFl", Val::Int(128)),
                        ("_i", opack::s("juno")),
                        ("_idsID", Val::Data(pairing.client_id.clone())),
                        ("_pubID", opack::s("juno")),
                        ("_sf", Val::Int(256)),
                        ("_sv", opack::s("170.18")),
                        ("model", opack::s("Juno")),
                        ("name", opack::s("Juno")),
                    ]),
                ));
                out.extend(Self::request(
                    inst,
                    "_sessionStart",
                    opack::dict([
                        ("_srvT", opack::s("com.apple.tvremoteservices")),
                        ("_sid", Val::Int(1)),
                    ]),
                ));
                out.extend(Self::request(
                    inst,
                    "FetchLaunchableApplicationsEvent",
                    opack::dict([]),
                ));

                let mut a = Args::new();
                a.insert("online".into(), json!(true));
                out.push(HostCall::notify(MEDIA, "online_changed", a));
                out
            }

            frame::E_OPACK => {
                // How tvOS says a command failed. Without reading it, a launch that the device
                // refused — an app that is not installed, a URL it would not open — looks
                // exactly like one that worked, because nothing else comes back either way.
                if let Some(why) = message.get("_em").and_then(Val::as_str) {
                    return vec![HostCall::warn(format!("apple-tv: {why}"))];
                }

                // The app list. This is what makes "watch Netflix" possible at all: the device's
                // apps are not knowable when the contract is written, so it says.
                let content = message.get("_c");
                if let Some(Val::Dict(map)) = content {
                    // tvOS answers with bundle id -> display name.
                    let mut names = Vec::new();
                    let mut bundles = driver_sdk::serde_json::Map::new();
                    for (bundle, name) in map {
                        if let Some(name) = name.as_str() {
                            names.push(name.to_string());
                            bundles.insert(name.to_string(), json!(bundle));
                        }
                    }
                    if !names.is_empty() {
                        names.sort();
                        inst.scratch
                            .insert("bundles".into(), Value::Object(bundles));
                        let mut a = Args::new();
                        a.insert("apps".into(), json!(names));
                        return vec![HostCall::notify(MEDIA, "apps_changed", a)];
                    }
                }
                Vec::new()
            }

            _ => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Setup flow
// ---------------------------------------------------------------------------------------

/// A field for typing an address by hand. Multicast is blocked on plenty of networks, so this
/// is not a fallback so much as the other half of the story.
fn typed_address() -> Field {
    Field {
        name: "address".into(),
        label: "Address".into(),
        kind: "string".into(),
        help: "for example 192.168.1.40 — on the Apple TV, Settings → Network".into(),
        default: None,
        options: Vec::new(),
        required: true,
    }
}

impl AppleTv {
    /// The value of the row that means "do not use the network at all".
    ///
    /// A sentinel rather than a separate question. IR has to be reachable when discovery found
    /// nothing *and* no address is known — an Apple TV behind an emitter has no address that
    /// means anything, and asking for one before offering IR makes the commonest reason to pick
    /// IR the one case where you cannot.
    const IR_ROW: &'static str = "__ir__";

    /// Offer what answered over mDNS, an address to type, and IR — all in one step.
    ///
    /// Unlike a Roku, there is nothing to enrich with a second request: the mDNS reply already
    /// carries the name somebody gave the television and the model, in its TXT record, and the
    /// port in its SRV. So this is one step rather than a walk through candidates.
    fn ask_for_address(state: &Value) -> (SetupStep, Value) {
        let found: Vec<&Value> = state
            .get("mdns_candidates")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter(|c| {
                        c.get("service")
                            .and_then(Value::as_str)
                            .is_some_and(|s| s.contains("companion"))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut rows: Vec<PickRow> = found
            .iter()
            .filter_map(|f| {
                let address = f.get("address")?.as_str()?.to_string();
                let port = f.get("port").and_then(Value::as_u64).unwrap_or(0);
                let txt = f.get("txt");
                let name = txt
                    .and_then(|t| t.get("Name"))
                    .and_then(Value::as_str)
                    .or_else(|| f.get("name").and_then(Value::as_str))
                    .unwrap_or("Apple TV")
                    .to_string();
                // `rpMd` is the hardware identifier — "AppleTV14,1" — which is the only thing
                // that tells two identically-named televisions apart before either is set up.
                let model = txt
                    .and_then(|t| t.get("rpMd"))
                    .and_then(Value::as_str)
                    .unwrap_or("Apple TV")
                    .to_string();
                Some(PickRow {
                    value: format!("{address}:{port}"),
                    cells: vec![name, model, address],
                    note: "apps, and can open a title".into(),
                })
            })
            .collect();

        let discovered = rows.len();

        // Always last, always there. An Apple TV on a VLAN the controller cannot reach, or one
        // somebody simply wants on an emitter, is not a failure to discover — it is a different
        // answer to the same question, and it needs no address at all.
        rows.push(PickRow {
            value: Self::IR_ROW.to_string(),
            cells: vec![
                "Use IR instead".into(),
                "IR emitter".into(),
                "no network".into(),
            ],
            note: "arrows, select, menu, play — no apps and no titles".into(),
        });

        let (title, body) = if discovered == 0 {
            (
                "No Apple TV answered".to_string(),
                "Nothing answered on the network. It has to be awake and on the same network as \
                 the controller — one asleep on ethernet still answers, one on Wi-Fi usually \
                 does not, and plenty of networks block multicast entirely.\n\nEnter its \
                 address by hand (Settings → Network on the device), or set it up for IR, which \
                 needs no address."
                    .to_string(),
            )
        } else {
            (
                format!(
                    "Found {discovered} Apple TV{}",
                    if discovered == 1 { "" } else { "s" }
                ),
                "Pick one to control it over the network — that is the only way to launch an \
                 app or open a title. IR is there for a box the controller cannot reach."
                    .to_string(),
            )
        };

        (
            SetupStep::Pick {
                title,
                body,
                columns: vec!["Name".into(), "Model".into(), "Address".into()],
                rows,
                field: "address".into(),
                manual: Some(typed_address()),
            },
            json!({ "phase": "mode" }),
        )
    }

    fn flow(&self, state: &Value, input: &Args) -> (SetupStep, Value) {
        let phase = state.get("phase").and_then(Value::as_str).unwrap_or("start");
        let get = |k: &str| {
            state
                .get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| input.get(k).and_then(Value::as_str).map(str::to_string))
        };

        match phase {
            "start" => Self::ask_for_address(state),

            // What was picked decides everything: the IR row is an answer, not a fallback, so
            // it finishes here without an address, a probe, or a pairing.
            "mode" => {
                let Some(address) = get("address") else {
                    return Self::ask_for_address(state);
                };

                if address == Self::IR_ROW {
                    return (
                        SetupStep::done(vec![Candidate {
                            label: "Apple TV (IR)".into(),
                            kind: "Apple TV".into(),
                            driver_id: "apple.tv.ir".into(),
                            properties: Default::default(),
                            verified: "IR only — bind an emitter to it, and see its README \
                                       about the codes"
                                .into(),
                            ..Default::default()
                        }]),
                        Value::Null,
                    );
                }

                let (host, port) = match address.rsplit_once(':') {
                    Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                        (h.to_string(), p.parse::<u16>().unwrap_or(49152))
                    }
                    // Typed by hand. Companion's port is announced over mDNS and is not fixed,
                    // so there is no good default — but something has to be tried.
                    _ => (address.clone(), 49152),
                };

                // M1. The Apple TV puts a code on screen when this arrives.
                let payload = opack::pack(&pairing_frame(srp::setup_start(), ("_pwTy", 1), 1));
                let Ok(bytes) = frame::encode(frame::PS_START, &payload, None, 0) else {
                    return (
                        SetupStep::Failed {
                            reason: "could not build the pairing request".into(),
                        },
                        Value::Null,
                    );
                };
                (
                    SetupStep::Session {
                        session: None,
                        open: Some(Connect {
                            host: host.clone(),
                            port: port as u16,
                            tls: false,
                            client_cert: None,
                            client_key: None,
                        }),
                        accept: None,
                        send: String::new(),
                        send_bytes: bytes,
                        read_ms: 5000,
                        close: false,
                        note: "asking the Apple TV to show a code".into(),
                    },
                    json!({ "phase": "asked", "host": host, "port": port }),
                )
            }

            // The salt and the device's public value came back; now somebody has to read the
            // code off the television.
            "asked" => {
                let received = received_bytes(input);
                let Some((salt, device_pub)) = pairing_reply(&received) else {
                    return (
                        SetupStep::Failed {
                            reason: pairing_failure(&received).unwrap_or_else(|| {
                                "the Apple TV did not answer as a Companion device. Check the \
                                 address, and that it is awake."
                                    .into()
                            }),
                        },
                        Value::Null,
                    );
                };

                let seed = random32();
                let client_id = uuid_like(&seed);
                let mut next = state.clone();
                next["phase"] = json!("pin");
                next["salt"] = json!(hex(&salt));
                next["device_pub"] = json!(hex(&device_pub));
                next["seed"] = json!(hex(&seed));
                next["client_id"] = json!(client_id);
                next["session"] = input.get("session").cloned().unwrap_or(Value::Null);

                (
                    SetupStep::Form {
                        title: "Enter the code on the television".into(),
                        body: "The Apple TV is showing a four-digit code. If it is not, it went \
                               to sleep before the request arrived — go back and try again."
                            .into(),
                        fields: vec![Field {
                            name: "pin".into(),
                            label: "Code".into(),
                            kind: "string".into(),
                            help: "as shown on screen".into(),
                            default: None,
                            options: Vec::new(),
                            required: true,
                        }],
                    },
                    next,
                )
            }

            // M3: prove we know the code.
            "pin" => {
                let pin = get("pin").unwrap_or_default();
                let (Some(salt), Some(device_pub), Some(seed), Some(client_id)) = (
                    get("salt").and_then(|s| unhex(&s)),
                    get("device_pub").and_then(|s| unhex(&s)),
                    get("seed")
                        .and_then(|s| unhex(&s))
                        .and_then(|v| <[u8; 32]>::try_from(v).ok()),
                    get("client_id"),
                ) else {
                    return (
                        SetupStep::Failed {
                            reason: "the pairing lost its place; start again".into(),
                        },
                        Value::Null,
                    );
                };

                let (_, tlv) = match srp::setup_prove(
                    &pin,
                    &salt,
                    &device_pub,
                    seed,
                    client_id.as_bytes().to_vec(),
                ) {
                    Ok(v) => v,
                    Err(e) => return (SetupStep::Failed { reason: e }, Value::Null),
                };

                let payload = opack::pack(&pairing_frame(tlv, ("_pwTy", 1), 2));
                let Ok(bytes) = frame::encode(frame::PS_NEXT, &payload, None, 0) else {
                    return (
                        SetupStep::Failed {
                            reason: "could not build the pairing proof".into(),
                        },
                        Value::Null,
                    );
                };

                let mut next = state.clone();
                next["phase"] = json!("proved");
                next["pin"] = json!(pin);
                (
                    SetupStep::Session {
                        session: state.get("session").and_then(Value::as_u64).map(|s| s as u32),
                        open: None,
                        accept: None,
                        send: String::new(),
                        send_bytes: bytes,
                        read_ms: 5000,
                        close: false,
                        note: "checking the code".into(),
                    },
                    next,
                )
            }

            // M5: the device proved it too. Hand over our identity.
            "proved" => {
                let received = received_bytes(input);
                let tlv = pairing_tlv(&received);
                if let Some(e) = tlv8::error(&tlv) {
                    return (SetupStep::Failed { reason: e }, Value::Null);
                }
                let Some(device_proof) = tlv8::get(&tlv, tlv8::PROOF) else {
                    return (
                        SetupStep::Failed {
                            reason: "the Apple TV sent no proof — the code may have been wrong"
                                .into(),
                        },
                        Value::Null,
                    );
                };

                let (Some(salt), Some(device_pub), Some(seed), Some(client_id), Some(pin)) = (
                    get("salt").and_then(|s| unhex(&s)),
                    get("device_pub").and_then(|s| unhex(&s)),
                    get("seed")
                        .and_then(|s| unhex(&s))
                        .and_then(|v| <[u8; 32]>::try_from(v).ok()),
                    get("client_id"),
                    get("pin"),
                ) else {
                    return (
                        SetupStep::Failed {
                            reason: "the pairing lost its place; start again".into(),
                        },
                        Value::Null,
                    );
                };

                // Rebuilt from state rather than carried: a driver is re-entered fresh for each
                // step and cannot hold a value across one. `setup_prove` is deterministic given
                // these five inputs, which is exactly why it takes the seed rather than making
                // its own.
                let setup = match srp::setup_prove(
                    &pin,
                    &salt,
                    &device_pub,
                    seed,
                    client_id.as_bytes().to_vec(),
                ) {
                    Ok((s, _)) => s,
                    Err(e) => return (SetupStep::Failed { reason: e }, Value::Null),
                };

                let tlv = match setup.setup_exchange(device_proof, "Juno") {
                    Ok(t) => t,
                    Err(e) => return (SetupStep::Failed { reason: e }, Value::Null),
                };
                let payload = opack::pack(&pairing_frame(tlv, ("_pwTy", 1), 3));
                let Ok(bytes) = frame::encode(frame::PS_NEXT, &payload, None, 0) else {
                    return (
                        SetupStep::Failed {
                            reason: "could not build the pairing exchange".into(),
                        },
                        Value::Null,
                    );
                };

                let mut next = state.clone();
                next["phase"] = json!("exchanged");
                (
                    SetupStep::Session {
                        session: state.get("session").and_then(Value::as_u64).map(|s| s as u32),
                        open: None,
                        accept: None,
                        send: String::new(),
                        send_bytes: bytes,
                        read_ms: 5000,
                        close: true,
                        note: "storing the pairing".into(),
                    },
                    next,
                )
            }

            // M6: keep what came back. This is the pairing.
            "exchanged" => {
                let received = received_bytes(input);
                let tlv = pairing_tlv(&received);
                if let Some(e) = tlv8::error(&tlv) {
                    return (SetupStep::Failed { reason: e }, Value::Null);
                }
                let Some(encrypted) = tlv8::get(&tlv, tlv8::ENCRYPTED_DATA) else {
                    return (
                        SetupStep::Failed {
                            reason: "the Apple TV did not send its identity back".into(),
                        },
                        Value::Null,
                    );
                };

                let (Some(salt), Some(device_pub), Some(seed), Some(client_id), Some(pin)) = (
                    get("salt").and_then(|s| unhex(&s)),
                    get("device_pub").and_then(|s| unhex(&s)),
                    get("seed")
                        .and_then(|s| unhex(&s))
                        .and_then(|v| <[u8; 32]>::try_from(v).ok()),
                    get("client_id"),
                    get("pin"),
                ) else {
                    return (
                        SetupStep::Failed {
                            reason: "the pairing lost its place; start again".into(),
                        },
                        Value::Null,
                    );
                };
                let setup = match srp::setup_prove(
                    &pin,
                    &salt,
                    &device_pub,
                    seed,
                    client_id.as_bytes().to_vec(),
                ) {
                    Ok((s, _)) => s,
                    Err(e) => return (SetupStep::Failed { reason: e }, Value::Null),
                };
                let pairing = match setup.setup_finish(encrypted) {
                    Ok(p) => p,
                    Err(e) => return (SetupStep::Failed { reason: e }, Value::Null),
                };

                let host = get("host").unwrap_or_default();
                let port = state.get("port").and_then(Value::as_u64).unwrap_or(49152);

                (
                    SetupStep::done(vec![Candidate {
                        label: "Apple TV".into(),
                        kind: "Apple TV".into(),
                        driver_id: "apple.tv".into(),
                        properties: [
                            ("Address".to_string(), json!(host)),
                            ("Port".to_string(), json!(port)),
                            ("Device id".to_string(), json!(hex(&pairing.device_id))),
                            ("Device key".to_string(), json!(hex(&pairing.device_ltpk))),
                            ("Controller id".to_string(), json!(hex(&pairing.client_id))),
                            ("Controller key".to_string(), json!(hex(&pairing.client_sk))),
                        ]
                        .into_iter()
                        .collect(),
                        verified: "paired over Companion".into(),
                        ..Default::default()
                    }]),
                    Value::Null,
                )
            }

            other => (
                SetupStep::Failed {
                    reason: format!("unknown setup phase `{other}`"),
                },
                Value::Null,
            ),
        }
    }
}

/// What core handed back from a `Session` step, as bytes.
fn received_bytes(input: &Args) -> Vec<u8> {
    input
        .get("received_bytes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect()
        })
        .unwrap_or_default()
}

/// The pairing TLV inside whatever frame arrived.
fn pairing_tlv(received: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut framer = frame::Framer::default();
    framer.feed(received);
    while let Some(Ok((_, payload))) = framer.next(None, 0) {
        if let Ok(message) = opack::unpack(&payload)
            && let Some(pd) = message.get("_pd").and_then(Val::as_data)
        {
            return tlv8::decode(pd);
        }
    }
    Vec::new()
}

fn pairing_reply(received: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let tlv = pairing_tlv(received);
    Some((
        tlv8::get(&tlv, tlv8::SALT)?.to_vec(),
        tlv8::get(&tlv, tlv8::PUBLIC_KEY)?.to_vec(),
    ))
}

fn pairing_failure(received: &[u8]) -> Option<String> {
    tlv8::error(&pairing_tlv(received))
}

/// A UUID-shaped identifier from bytes we already have.
///
/// HAP wants the controller's pairing identifier to look like a UUID and to be stable. A driver
/// has no clock and no UUID crate here, and the seed is already random — so this formats it
/// rather than adding a dependency to generate a second random thing.
fn uuid_like(seed: &[u8; 32]) -> String {
    let h = hex(&seed[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
    .to_uppercase()
}

export_driver!(AppleTv);

#[cfg(test)]
mod hold_tests {
    use super::*;

    /// An instance with a session already up, so `send` produces frames rather than a warning.
    fn connected() -> Instance {
        let mut inst = Instance::new(1);
        inst.scratch.insert("write".into(), json!(hex(&[1u8; 32])));
        inst.scratch.insert("read".into(), json!(hex(&[2u8; 32])));
        inst.scratch.insert("out".into(), json!(0));
        inst.scratch.insert("in".into(), json!(0));
        inst
    }

    fn frames(calls: &[HostCall]) -> usize {
        calls
            .iter()
            .filter(|c| matches!(c, HostCall::Tx { .. }))
            .count()
    }

    fn warned(calls: &[HostCall]) -> bool {
        calls
            .iter()
            .any(|c| matches!(c, HostCall::Log { level, .. } if level == "warn"))
    }

    /// A tap is two frames — press and release. A hold is one, and the device repeats on its
    /// own until the second arrives. Sending both for a hold is just a tap, and the ramp never
    /// happens.
    #[test]
    fn a_hold_presses_without_releasing_and_a_tap_does_both() {
        let d = AppleTv;
        let mut inst = connected();

        let tap = d.on_command(&mut inst, MEDIA, "volume_up", &Args::new());
        assert_eq!(frames(&tap), 2, "a tap is press and release");

        let mut inst = connected();
        let hold = d.on_command(
            &mut inst,
            MEDIA,
            "hold",
            &Args::from([("what".to_string(), json!("volume_up"))]),
        );
        assert_eq!(frames(&hold), 1, "a hold presses and stops there");
        assert_eq!(AppleTv::held(&inst), Some(hid::VOLUME_UP));

        let release = d.on_command(&mut inst, MEDIA, "release", &Args::new());
        assert_eq!(frames(&release), 1);
        assert_eq!(AppleTv::held(&inst), None, "the key is no longer held");
    }

    /// One finger, one button. A second hold has to let go of the first, or the first key is
    /// down forever with nothing left that names it — and on volume that runs to the top.
    #[test]
    fn a_second_hold_releases_the_first() {
        let d = AppleTv;
        let mut inst = connected();

        d.on_command(
            &mut inst,
            MEDIA,
            "hold",
            &Args::from([("what".to_string(), json!("volume_up"))]),
        );
        let second = d.on_command(
            &mut inst,
            MEDIA,
            "hold",
            &Args::from([("what".to_string(), json!("down"))]),
        );

        assert_eq!(
            frames(&second),
            2,
            "letting go of the old key and pressing the new one"
        );
        assert_eq!(AppleTv::held(&inst), Some(hid::DOWN));
    }

    /// Releasing nothing is not an error — a rule that brackets a hold will do it after a
    /// reconnect cleared the state, and a warning there is a log line every time somebody lets
    /// go of a button.
    #[test]
    fn releasing_nothing_is_quiet() {
        let d = AppleTv;
        let mut inst = connected();
        let out = d.on_command(&mut inst, MEDIA, "release", &Args::new());
        assert!(out.is_empty(), "nothing to say and nothing to send");
    }

    /// The contract lists keys this box does not have. tvOS scrubs by holding an arrow, so
    /// there is no scan key to map — and mapping it to one that moves the wrong way would be
    /// worse than refusing.
    #[test]
    fn a_key_this_box_does_not_have_is_refused_by_name() {
        let d = AppleTv;
        let mut inst = connected();
        let out = d.on_command(
            &mut inst,
            MEDIA,
            "hold",
            &Args::from([("what".to_string(), json!("scan_forward"))]),
        );
        assert!(warned(&out), "an unsupported key should say so");
        assert_eq!(frames(&out), 0);
        assert_eq!(AppleTv::held(&inst), None);
    }

    /// A dropped connection must not leave a key remembered as held: the release cannot be sent
    /// down a socket that is gone, and the next connection would send one for nothing.
    #[test]
    fn reconnecting_forgets_a_held_key() {
        let d = AppleTv;
        let mut inst = connected();
        d.on_command(
            &mut inst,
            MEDIA,
            "hold",
            &Args::from([("what".to_string(), json!("left"))]),
        );
        assert!(AppleTv::held(&inst).is_some());

        d.on_bind(&mut inst);
        assert_eq!(AppleTv::held(&inst), None);
    }
}
