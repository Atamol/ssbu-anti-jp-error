## [日本語はこちら](README.md)

# ssbu-anti-jp-error

A Skyline plugin that counters the "avaru error" griefing attack in Super Smash Bros. Ultimate.
It detects opponents who deliberately trigger disconnect errors on you and shuts the attack down before it lands.
For background on what the attack actually is, see [What is the avaru error?](#what-is-the-avaru-error) below.

## What it does

When a matchmaking response carrying a cheater's signature comes back from the server, the plugin rewrites that response into "an empty session I host myself".
The game then skips the P2P phase without raising an error, drops back to training mode, and automatically kicks off a new search. No penalty is applied.
It also remembers blocked players and filters them out the moment their ID shows up in a future session.

### Detection

A session is flagged as a cheater if any of the following is true:

- `application_buffer[0] == 0x02` (a constant marker the avaru tools leave behind)
- `max_participants > 2` (a session set up for 3 or more players when you queued 1v1)
- A PID that's already on the learned blocklist

On detection a small popup briefly shows up with the opponent's name and closes itself after a few seconds.

## Re-search wait time

After a detection, the next match typically takes **30 seconds to 2 minutes** to come through.
This is driven by the server's renotification cadence, and it's not clear yet whether the client can shorten it further. Improvements are being explored (the current release is a prototype since nothing public does this at all).

## Download

Grab the NRO from the [release page](https://github.com/Atamol/ssbu-anti-jp-error/releases).

## Requirements

- Game version 13.0.4
- Atmosphère and Skyline (CFW setup)

## Notes

- The re-search wait described above is expected behavior for now, not a bug
- Detection is kept conservative, but false positives aren't guaranteed to be zero (the people actually running this attack get caught 100%, but other session types might occasionally trip the rules)
- This is still a prototype. If you hit unexpected behavior, open an issue or DM me somewhere

---

# What is the avaru error?

The **avaru error** (also called "SK error") is a griefing exploit against SSBU's online matchmaking, mostly observed on the Japanese servers. The name comes from the perpetrators using an existing top player's in-game tag without permission (the actual player is uninvolved, and this is well known within the scene).

### How it works

When you search for an opponent in quickplay or Elite Smash, NEX's matchmaking server assigns you to a session. Normal 1v1 gives `max_participants = 2`, but cheaters use CFW (custom firmware) to manipulate this:

**4/4 variant**: they create a session with `max_participants = 4` even though it's supposed to be 1v1. Several regular players get pulled into the same session, the game sees it as "full", and throws an error. Every victim's disconnect counter goes up.

**2/2 variant**: session metadata looks normal (`max_participants = 2`), but something in the PIA connection phase gets forced into an error state. The victim's disconnect counter still goes up.

In both cases:
- The NEX server doesn't return any error (it doesn't see anything wrong)
- The Switch's "Recent Players" list ends up showing one cheater account alongside 2-3 regular players who got caught
- Cheaters cycle through a lot of accounts (probably CFW-spoofed)

### Why this is a problem

- **Switch's block function doesn't help** — even if you fill every block slot, they just come at you from new accounts
- **Only the victim gets punished** — GSP doesn't shift either way, but the disconnect counter hits only the victim even though the cheater is the one causing it. Accumulate enough and you run into matchmaking restrictions and other system-level penalties
- **Higher GSP means more encounters** — cheaters typically inflate their rank with other one-sided tactics (lag switching, stock+FS rulesets on Game & Watch, etc.), so at the top end you run into them constantly. An hour of play can turn into a handful of actual matches
- **Nintendo can't see it** — every RMC response on the NEX side comes back normal, so the server has no signal that something's wrong

### What's been figured out

| Finding | Detail |
|---------|--------|
| 4/4 variant is detectable | `max_participants > 2` in a 1v1 session |
| NEX sees nothing wrong | every RMC response is a success, no server-side visibility |
| Each attack hits multiple victims | NAT traversal (proto=14 method=1) fires 4+ times instead of the usual 2 |
| Dropping PIA packets dodges the penalty | discarding PIA traffic from a suspect session prevents the disconnect counter from going up |
| `app_buf[0]` distinguishes session types | `0x01` = self-hosted (normal), `0x02` = 2/2 variant, `0x03`/`0x04`/`0x06` = 4/4 variant, `0x05`/`0x09` = normal |
| Player name is recoverable | UTF-16LE at `app_buf+0x1e` holds the session owner's name |
