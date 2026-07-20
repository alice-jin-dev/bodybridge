# bodybridge

> Connect embodied devices to cloud AI via MCP.
> 具身 × 云端 MCP 桥

**Zero API cost · No PC required · Fully self-hosted**

*One wide bridge, not many narrow ones.*

---

## What is this

bodybridge is an open-source cloud bridge that connects embodied devices
(StackChan, Raspberry Pi, ESP32, and more) to AI through claude.ai custom connectors.

Built on the open MCP protocol — any MCP-compatible AI client can connect.

Instead of writing a separate bridge for every device, bodybridge gives you
one bridge with a standard slot: implement three methods, and your device is in.

**Why bodybridge:**

- **Zero API cost** — Runs on your existing Claude subscription. No extra token billing for the brain (LLM inference).
- **No PC required** — Cloud-hosted. No need to keep a machine running at home.
- **Fully self-hosted** — Your data and keys stay with you.

---

## Architecture

Four layers, each with one job:

| Layer | Responsibility |
|---|---|
| **MCP Server** | Exposes tools over streamable-http; receives tool calls from the AI |
| **Auth** | Token verification. Secrets live in environment variables, never in code |
| **Device Adapter Slot** | Standard interface: `send_command` / `get_status` / `list_capabilities`. Swap devices by implementing the same interface — the bridge itself stays untouched |
| **Reflex** *(optional)* | Device-local instant reactions, independent of the AI |

**Design philosophy: flexible at the top, solid in the middle, rule-based at the bottom.**

> A puppy that doesn't understand you tilts its head — it doesn't run wild.
> 小狗听不懂你说话，会歪头看你，而不是乱跑。

When the AI can't understand, or the device can't comply, the bridge says so
honestly instead of guessing. That refusal *is* the safety mechanism.

---

## Which version should I use?

| | **V1 (current)** | **V2 (planned)** |
|---|---|---|
| What it does | Motion control (turn, light up, move…) | Everything in V1 + streaming interaction (voice first) |
| Interaction | Request-response | Request-response + streaming |
| Required config | **2 items** (token + password), +1 for public deployment (public URL) | Several (token + storage + voice service credentials) |
| External dependencies | **None** | Likely additional services |

**Choose V1 if** you just want the AI to control device actions — minimal, readable, stable, zero dependencies.
**Wait for V2 if** you need real-time voice conversation, or other streaming scenarios (video, sensor feeds).

> Each version is a complete, standalone release.
> More features isn't always better — for those who don't need them, they're just weight.

---

## Quick Start

*Coming soon — pending real-device validation.*

---

## Deployment

> **Upgrading an existing deployment?** Authentication changed from a static
> token to OAuth 2.1 in this version. See [MIGRATION.md](MIGRATION.md) for
> what's different and what you need to do.

### ⚠️ Public HTTPS address required

claude.ai's custom connectors require a trusted SSL certificate — self-signed
certs don't work — and the CIMD discovery flow needs Anthropic's servers to
reach this bridge from the outside. So before connecting to claude.ai, you
need a real, publicly reachable HTTPS address for the bridge.

Set `BODYBRIDGE_PUBLIC_URL` to that address: scheme + host (+ port), no
trailing slash, no `/mcp` path (the code appends that itself). Example:
`BODYBRIDGE_PUBLIC_URL=https://bridge.example.com`.

**This value must match, character for character, the URL you type into
claude.ai when adding the connector** — scheme, host, port, path, and
trailing slash all included. A mismatch fails resource validation and the
connection is rejected.

If unset, the bridge still starts (it falls back to a local address and
prints a warning) — but CIMD discovery can't work, so it *runs* while being
unreachable from claude.ai. Starting successfully is not the same as being
configured correctly.

On one-click deploy platforms, the domain is usually only assigned after
deployment finishes — so the order is: deploy first, get the domain, then
set `BODYBRIDGE_PUBLIC_URL` and restart.

### ⚠️ Choosing a deployment region

The bridge must be deployed somewhere that satisfies **both**:

1. **Can reach claude.ai** — otherwise the bridge can't connect to the AI
2. **Can be reached by your device** — otherwise your device can't connect to the bridge

Please choose a region appropriate for your network environment.

### Network quality

- **V1 (motion control)** — Latency-tolerant. Most networks are fine.
- **V2 (voice, planned)** — Real-time voice is latency-sensitive. Network quality directly affects the experience.

---

## Bring your own device

*Adapter guide coming soon.*

Implement three methods of `DeviceAdapter`, and your device plugs into bodybridge:

- `send_command(command, params)` — send one explicit command
- `get_status()` — query current state
- `list_capabilities()` — report what the device can do

---

## Tech stack

- Python 3.10+
- [MCP official SDK](https://github.com/modelcontextprotocol/python-sdk) (FastMCP)
- Transport: streamable-http, stateless by default

Architecturally a thin core with a plugin slot — the microkernel pattern.

---

## License

MIT

## Author

[alice-jin-dev](https://github.com/alice-jin-dev)
