# Apple TV

One product, two ways in. The package carries both and setup asks which.

| | `apple.tv` | `apple.tv.ir` |
|---|---|---|
| how | Companion, over the network | IR emitter |
| runtime | native plugin | `commands.toml`, no code |
| apps | yes, read from the device | no |
| **open a title** | **yes** | no |
| d-pad, play/pause, menu | yes | yes |
| volume | up/down, over HDMI-CEC | no |

An IR-only install never loads the plugin — the package loader builds each driver from the
runtime its own manifest declares.

## Why this is worth having

`_launchApp` takes a bundle identifier **or a URL**, so "play Severance in the den" resolves to
a link and the television goes straight to it. Nothing else in this class of hardware does
that; the market-leading Apple TV integration is a d-pad and a play button.

The path was already in the contract — `launch_app` has taken `content_id` since the Roku
driver — and `has_deep_link` is what says this box honours it.

## Setting it up

1. The Apple TV must be awake and on the same network. One asleep on ethernet still answers;
   on Wi-Fi it usually does not.
2. Pick it from the list. It is found over mDNS on `_companion-link._tcp`, and the port comes
   from the SRV record — it is not fixed, which is why `Port` is a device property.
3. Choose **Network**.
4. A four-digit code appears on the television. Type it in.

That pairing is stored as four properties and reused on every connection afterwards. If the
Apple TV is factory reset, the stored key stops matching and setup has to be run again — the
driver says so rather than failing quietly.

For **IR**, choose it at step 3 and bind an emitter to the driver's IR connection. See the note
in `commands.toml`: the code names are right, the pronto payloads are blank on purpose.

## Deep links rot

They are not an API anybody promised. Netflix's stopped working in September 2025 and
Paramount+'s before that. `src/links.rs` is a table for that reason, and a service that is
unknown or known-dead **still launches** — by bundle id, on its home screen — and says that is
what happened. Reporting success for a link that silently did nothing is the failure this is
designed against.

Working, as of writing: Apple TV, Disney+, YouTube, Hulu, Peacock, Pluto, Spotify.

## What is not here

**Now-playing metadata and artwork.** They live in MRP, which since tvOS 15 is only reachable
tunnelled inside AirPlay 2 — a second protocol stack for information nothing has asked for yet.
`has_metadata` is not declared, rather than declared and empty.

**Siri.** Streaming voice to an Apple TV is HomeKit's Target Control, not Companion: a separate
accessory role, Opus over HomeKit Data Stream, and Apple's own specification and ADK are both
marked non-commercial. That is a licensing decision, not a technical one.

**Power.** An Apple TV has no discrete power state to command. `on`/`off` are absent rather
than faked with a menu press.

## Verification status

The codecs and the crypto are tested: 31 unit tests covering OPACK's back-reference table,
TLV8's 255-byte fragmentation, SRP padding, nonce alignment, frame length including the auth
tag, and the session counter. Every one of those fails silently when wrong, which is why they
are tested rather than eyeballed.

**The handshake has not been run against real hardware.** The vectors are self-consistent and
follow pyatv's implementation, but nothing has proved they agree with what an Apple TV
computes. The first thing to do with a real device is pair one.
