# Security Policy

bodybridge is a thin, self-hosted MCP bridge. It stores no business data,
touches no database, runs no JavaScript, and pulls in no external resources,
so its attack surface is intentionally small. This document explains how to
report a problem, which versions are maintained, and — just as importantly —
what v1 deliberately does not defend against.

## Reporting a Vulnerability

Please report security issues privately, not through public issues or pull
requests (a public report is a public disclosure before a fix exists).

Use GitHub's private vulnerability reporting: on this repository's
**Security** tab, click **Report a vulnerability** to open a private report
form. This goes straight to me and stays private until a fix is ready.

Please include:

- a description of the issue
- steps to reproduce
- any relevant logs or proof-of-concept
- your assessment of the impact

I aim to respond within a few days.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅        |
| < 1.0   | ❌        |

Only the latest major version receives security fixes.

## What This Bridge Does Not Defend Against (by design)

Some things are explicitly out of scope for v1. Naming them is more honest
than pretending everything is covered.

- **A leaked device credential grants device control.** There is no second
  factor on the device link; treat the device token like a password, and
  regenerate it (and restart) if it is ever exposed.
- **The device link authenticates once, not per message.** The long-lived
  connection is trusted after the initial handshake.
- **No automatic credential rotation.** v1 has no built-in rotation; a leaked
  secret is replaced manually.
- **Offline means failure, not a queue.** If a device is offline, commands
  fail honestly and are reported as such — they are not queued, retried, or
  answered from a stale cached state. This is deliberate: stale data would
  mislead the model.
- **Networks with a human-facing sign-in page are out of scope.** Hotel,
  airport, and campus captive portals assume a person at a browser, which an
  unattended deployment does not have. Use a phone hotspot or an ordinary
  network.

## A Note on Adapters

The adapter runs in the same process as the bridge and carries out whatever a
connected device's firmware asks of it. The security of any given deployment
therefore includes the security of the adapter you run: a device that can only
toggle an LED is very different from one that can act on a general-purpose
system. Choose and audit your adapter accordingly.

Device messages (the `message` field of a result) are passed through to the
MCP client unchanged. This is standard for MCP servers: the protocol places
the data-versus-instruction trust boundary at the client, not at the bridge,
and the bridge does not inspect or filter message text. If you connect a
device whose firmware you do not control, treat its messages as untrusted
content — the same as any text entering a model's context.

## Coordinated Disclosure

Once a report is received, I will investigate, prepare a fix, release a new
version, and — if you wish to be credited — acknowledge you in the release notes.
