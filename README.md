# bodybridge

> Connect embodied devices to cloud AI via MCP.
> 具身 × 云端 MCP 桥

**Zero API cost · No PC required · Fully self-hosted**

*One wide bridge, not many narrow ones.*

---

## What is this

bodybridge is an open-source, self-hosted MCP bridge that lets embodied
devices — StackChan, Raspberry Pi, ESP32, and more — be driven by an AI. Any
MCP-compatible client can connect; through the claude.ai connector it runs on
your existing subscription, so the brain (LLM inference) costs nothing extra.

Instead of writing a separate bridge for every device, bodybridge gives you
one bridge with a standard slot: implement three methods, and your device is in.

**Why bodybridge:**

- **Zero API cost (on the claude.ai path)** — Runs on your existing Claude subscription; no extra token billing for the brain (LLM inference). Other MCP clients can connect too, but as of now claude.ai is the only path where a personal subscription covers programmatic use — others bill per token. See [Deploy](#deploy).
- **No PC required** — Cloud-hosted. No need to keep a machine running at home.
- **Fully self-hosted** — Your data and keys stay with you.

---

## Architecture

Four layers, each with one job:

| Layer | Responsibility |
|---|---|
| **MCP Server** | Exposes tools over streamable-http; receives tool calls from the AI |
| **Auth** | OAuth 2.1 authorization-code flow with PKCE; stateless JWT verification on every request. Client identity via Dynamic Client Registration (default) or CIMD, switchable. Secrets live in environment variables, never in code |
| **Device Adapter Slot** | Standard interface: `send_command` / `get_status` / `list_capabilities`. Swap devices by implementing the same interface — the bridge itself stays untouched |
| **Reflex** *(planned, not in V1)* | Device-local instant reactions, independent of the AI. Not implemented in V1 — the layer is reserved in the architecture, not shipped |

**Design philosophy: flexible at the top, solid in the middle, rule-based at the bottom.**

> A puppy that doesn't understand you tilts its head — it doesn't run wild.
> 小狗听不懂你说话，会歪头看你，而不是乱跑。

When the AI can't understand, or the device can't comply, the bridge says so
honestly instead of guessing. That refusal *is* the safety mechanism.

---

## What V1 does

| | **V1** |
|---|---|
| What it does | Motion control (turn, light up, move…) |
| Interaction | Request-response |
| Required config | **3 items** (token, password, public URL) — all mandatory; the bridge won't start without them |
| External dependencies | **None** |

V1 lets the AI control device actions — minimal, readable, stable, zero dependencies.

---

## Quick Start

bodybridge is an MCP bridge: it connects embodied devices (ESP32, Raspberry
Pi, StackChan…) to any MCP-compatible AI client. claude.ai is the primary
path — and the only one where the AI runs on your existing subscription with
no extra API bill (see [Deploy](#deploy)).

This section gets a working bridge running on your own machine in about five
minutes. Connecting it to an AI client comes after, under Deploy.

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (`pip install uv`, or see uv's docs)

### Steps

```bash
# 1. Clone
git clone https://github.com/alice-jin-dev/bodybridge.git
cd bodybridge

# 2. Configure — copy the template and fill in the three required values
cp .env.example .env
#    Then open .env and set all three (the bridge won't start until you do):
#
#      BODYBRIDGE_TOKEN      — the JWT signing secret. Generate a strong one:
#          python -c "import secrets; print(secrets.token_urlsafe(32))"
#
#      BODYBRIDGE_PASSWORD   — the password gate for /oauth/authorize.
#          Any non-empty string works; a strong random one is recommended
#          (you can use the same command as above).
#
#      BODYBRIDGE_PUBLIC_URL — the bridge's public base URL. Not a secret.
#          For a local run:  http://127.0.0.1:8000
#          No trailing slash, no /mcp — the bridge appends that itself.
#
#    The bridge auto-loads .env on startup, so no extra flags are needed.

# 3. Install dependencies
uv sync

# 4. Run
uv run python server.py
```

If it started, you'll see:

```
[bodybridge] starting on 0.0.0.0:8000 (port source: BODYBRIDGE_PORT)
```

(You may also see a warning that `BODYBRIDGE_DEVICE_TOKEN` is not set — that's
expected for a local run; the `/device` endpoint stays disabled until you set
it, which is what you'll do when you attach a device.)

That's the bridge itself running. It has no device attached yet — that's
expected. `get_status` will report `offline` until a device connects.

> **Not seeing it start?** If the bridge exits immediately, you most likely
> left `BODYBRIDGE_TOKEN`, `BODYBRIDGE_PASSWORD`, or `BODYBRIDGE_PUBLIC_URL`
> empty — all three are required.

### Deploy

For an AI client to reach your bridge, it needs to be on a public HTTPS URL.
In short: deploy to any platform that gives you HTTPS (the project runs on
Zeabur), set the same variables in the platform's Variables panel (not a `.env`
file), plus `BODYBRIDGE_PUBLIC_URL` so OAuth discovery works. The full
walkthrough is in [Deployment](docs/deployment.md).

**With claude.ai (recommended).** Add the bridge as a custom connector in
claude.ai. Because the AI runs on your existing claude.ai subscription, this
path adds no per-token API bill — your device gets a brain for the price of a
subscription you already pay for.

**With other MCP clients.** The bridge speaks standard MCP, so any
MCP-compatible client can connect to it with little or no change on the
bridge side. (Note: only the claude.ai path is subscription-covered; other
clients bill on their own terms.)

### Bring your own device

Want to connect real hardware? See
[Connecting a device](docs/connecting-a-device.md). You don't write an
adapter and you don't download anything — your device just speaks the
bridge's protocol. On an ESP32 that's five steps to a blinking LED.

The two guides split the job: [Connecting a device](docs/connecting-a-device.md)
is the general one — the protocol any device has to speak. The
[firmware guide](firmware/README.md) is ESP32-specific — the sketch itself,
the Arduino IDE setup, and flashing it to the board.

---

## Deployment

> **Upgrading an existing deployment?** Authentication changed from a static
> token to OAuth 2.1 in this version. See [MIGRATION.md](MIGRATION.md) for
> what's different and what you need to do.

**The bridge has to run on a cloud host that is publicly reachable over
HTTPS.** A client's servers — Anthropic's, on the claude.ai path — perform
OAuth discovery against the bridge from the outside, and custom connectors
require a certificate a public client will trust. A self-signed cert or a
LAN-only address will not do. Which host you use is up to you; the bridge is
not tied to any platform.

The shortest path: deploy to a host that gives you HTTPS, set the three
required variables in its variables panel, then set `BODYBRIDGE_PUBLIC_URL` to
the domain it assigned you and restart. Most platforms only hand out that
domain after the first deploy, so expect to start the bridge twice.

**`BODYBRIDGE_PUBLIC_URL` must match, character for character, the URL you type
into your MCP client when adding the connector.** A mismatch fails resource
validation and the connection is rejected — while the bridge keeps running and
logging nothing unusual. Write it with no trailing slash and no `/mcp` path.

**→ [Deployment](docs/deployment.md)** — the full walkthrough: what to require
of a host, a worked example, three read-only checks that tell you it worked,
and what each failure mode looks like.

---

## Bring your own device

Any device you can program — ESP32, Raspberry Pi, anything that can run a
WebSocket client — connects by speaking the bridge's protocol. You don't write
an adapter and you don't download anything: the generic WebSocket adapter
already ships inside the bridge.

**→ [Connecting a device](docs/connecting-a-device.md)** — the five-step ESP32
path, the minimum contract for any other device, and what to check when it
won't connect.

Writing an adapter is a different job, and only for devices that can't run a
WebSocket client at all — a finished commercial product, or hardware that
speaks its own protocol.

### Before a device connects

Until a real device is connected, the three device tools return an `offline`
result (for example, `get_status` reports that the device isn't connected).
**This is the correct, healthy state — not an error.** It means the bridge is
up and waiting for a device; it does not mean anything is misconfigured. Once
your device connects to the `/device` endpoint, the tools begin reflecting its
real state.

---

## Tech stack

- Python 3.10+
- [MCP official SDK](https://github.com/modelcontextprotocol/python-sdk) (FastMCP)
- MCP specification: 2025-11-25
- Transport: streamable-http, stateless by default

Architecturally a thin core with a plugin slot — the microkernel pattern.

> More features isn't always better — for those who don't need them, they're just weight.

---

## Changelog

Release history is in [CHANGELOG.md](CHANGELOG.md).

## License

MIT

## Author

[alice-jin-dev](https://github.com/alice-jin-dev)
