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
| hold a key (ramp) | arrows and volume | arrows |

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

For **IR**, pick the "Use IR instead" row — it is always in the list, whether or not anything
was discovered, and needs no address. Then bind an emitter to the driver's IR connection.

The codes are the aluminium Apple Remote's, which every Apple TV including the 4K still
accepts. There is no IR **Home**: on the remote it is a *hold* of Menu, and a single emitted
code cannot express a hold. It is left out rather than aliased to Menu — Menu goes back one
level, which is not the same thing, and an emitter refusing a code it does not have is better
than quietly doing something else.

## Holding a key

`hold {what}` and `release` bracket a ramp — a keypad's `held`/`released` drives them directly.
Tapping `down` forty times is a different gesture from holding it, and both ends of the driver
treat it that way: over the network a hold is a press with no release, so tvOS repeats on its
own; over IR it is `start_repeat`, so the emitter keeps the carrier up rather than re-sending
frames.

One key at a time. A second `hold` lets go of the first — two keys down at once is a state
nothing can get out of, and on volume it runs to the top of the range.

Each variant is only *offered* the keys it has. `hold`'s `what` is gated per value by the
capability that provides it, so the assistant and the validation gate both see arrows only on
the IR driver, and arrows plus volume on the network one. Neither is offered a scan key,
because tvOS has none — scrubbing *is* a hold of left or right, and aliasing it to something
that moves the wrong way would be worse than not having it.

Over IR, volume is absent for a real reason: an Apple Remote has no volume buttons at all,
since volume belongs to whatever the box is plugged into.

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
