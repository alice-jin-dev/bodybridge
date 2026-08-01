# Configuration reference

Every setting the bridge reads, what it does, and what happens when you get it
wrong. `.env.example` is the template you copy; this is the manual you look
things up in.

The bridge reads its configuration from environment variables. On startup it
also loads a `.env` file sitting next to `server.py`, so local development
needs nothing more than that file. Variables already present in the
environment are **never** overwritten by `.env` — a platform-injected value
(Zeabur, Railway, Render, …) always wins over the file.

Three variables are mandatory: without any one of them the bridge prints an
explanation and exits with status 1. Everything else has a default. Almost
every optional variable also tolerates a bad value: it warns, falls back, and
carries on. The exceptions are called out explicitly below.

---

## Quick start

Copy `.env.example` to `.env` and fill in three values:

```sh
# Minimum working configuration.

# Signing secret for the tokens the bridge issues. Server-side only.
# Generate your own (below) — never a value that has been public anywhere.
BODYBRIDGE_TOKEN=

# Password you type on the consent page when a client asks to connect.
# Generate it the same way, and make it different from the one above.
BODYBRIDGE_PASSWORD=

# The bridge's public base URL. No trailing slash, no /mcp.
# Your own address, e.g. https://your-bridge.example.com — not a usable value.
BODYBRIDGE_PUBLIC_URL=
```

For local development, point the last one at your own machine instead:

```sh
BODYBRIDGE_PUBLIC_URL=http://127.0.0.1:8000
```

Generate the two secrets with:

```sh
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Run them separately — the two values must be different, and neither should
ever be committed. That is all you need to start the bridge. To connect a
physical device you will also want `BODYBRIDGE_DEVICE_TOKEN`; see
[Optional](#optional).

---

## Required

These three are checked in this order at startup. The first one missing wins:
the bridge prints why and exits 1 without checking the rest.

### `BODYBRIDGE_TOKEN`

- **What it is**: the HMAC signing key for every token the bridge issues —
  access tokens, authorization codes, and (in `dcr` mode) the self-signed
  `client_id` handed back at registration.
- **Why it must be set**: it is what makes an issued token unforgeable. There
  is no safe default; a guessable one would let anyone mint tokens for your
  bridge.
- **How to fill it**: a long random string, from the `secrets.token_urlsafe`
  command above.
- **If unset**: startup is refused (exit 1) with a message naming the
  variable. Whitespace-only counts as unset — the value is stripped first.
- **Note**: this is a server-side secret. It is never sent to a client and
  never sent to a device. See [Easy to confuse](#easy-to-confuse) before you
  put anything resembling it into firmware.
- **Rotating it invalidates every token already issued**, all at once. Tokens
  are stateless and signed with this key, so there is no per-token revocation.

### `BODYBRIDGE_PASSWORD`

- **What it is**: the password gating `/oauth/authorize`, the consent page an
  MCP client sends you to when it wants access.
- **Why it must be set**: that page is the only way a client can obtain a
  token. With no password the flow can never succeed, so the bridge fails fast
  rather than starting up with authorization silently broken.
- **How to fill it**: a long random string, generated the same way — and
  different from `BODYBRIDGE_TOKEN`.
- **If unset**: startup is refused (exit 1). Whitespace-only counts as unset.
- **Note**: unlike the other two, you type this one by hand, on the consent
  page, each time a new client connects.

### `BODYBRIDGE_PUBLIC_URL`

- **What it is**: the bridge's public base URL — scheme, host, and port if
  non-standard. Nothing else.
- **Why it must be set**: every field of the OAuth discovery metadata
  (`issuer`, `resource`, and the three endpoint URLs), the `iss` and `aud`
  claims of every token, and the RFC 9207 `iss` on every authorization
  response are all derived from this one value. An MCP client that reads
  metadata built on the wrong base URL cannot discover the bridge, and a token
  minted with the wrong `aud` fails validation on the way back in.
- **How to fill it**: `https://your-bridge.example.com` for a public
  deployment; `http://127.0.0.1:8000` for local development. **No trailing
  slash and no `/mcp` path** — the bridge appends `/mcp` itself.
- **If unset**: startup is refused (exit 1). This used to fall back to a local
  address and start anyway, which produced a bridge that looked healthy —
  serving, health check passing, no errors in the log — while no client could
  actually use it. The fallback is gone.
- **If set but malformed** (does not start with `http://` or `https://`): this
  is **not** fatal. The bridge warns, falls back to a local address, and
  starts. Only the missing case refuses startup.
- **If it has a trailing slash**: stripped automatically, with a note printed
  at startup. Nothing breaks.
- **It must match, character for character, the URL you type into your MCP
  client** when adding the connector. A mismatch fails resource validation and
  the connection is rejected.

---

## Optional

Everything below has a working default. Unless stated otherwise, an invalid
value is **not** fatal: the bridge prints a warning, uses the default, and
starts normally. You will not lose the service to a typo.

### `BODYBRIDGE_DEVICE_TOKEN`

- **Default**: unset.
- **Controls**: the Bearer credential a physical device presents when it opens
  the `/device` WebSocket connection. The bridge compares it in constant time.
- **When you'd set it**: whenever you want to connect real hardware. Use a
  long random string, generated the same way as the two required secrets, and
  put the identical value in the firmware's `secrets.h`.
- **If unset**: `/device` is disabled and every device connection is refused.
  The bridge still starts, and `/mcp` and the OAuth endpoints are unaffected.
  If the active adapter supports direct connections, a warning is printed at
  startup explaining that the endpoint is off; adapters that do not support
  direct connections stay quiet, so you are not nagged about a variable you do
  not need.
- **Invalid values**: not applicable — any non-empty string is a valid
  credential. If it does not match what the device presents, the handshake is
  refused with a silent 403.

### `BODYBRIDGE_HOST`

- **Default**: `0.0.0.0` (all interfaces).
- **Controls**: the network interface the bridge binds to.
- **When you'd change it**: set `127.0.0.1` if you want local-only access, for
  example when running behind your own reverse proxy. On a cloud platform you
  normally leave it alone.
- **If unset**: the default is used silently, with no warning.
- **⚠️ If invalid**: this is the one variable with **no validation and no
  fallback**. The value is handed to the server as-is, and an address that
  cannot be bound raises an error at startup. A typo here does stop the bridge
  — unlike every other optional variable.

### `PORT`

- **Default**: unset. Read **first**, ahead of `BODYBRIDGE_PORT`.
- **Controls**: the TCP port to listen on. This is the variable most cloud
  hosts inject automatically to tell an application where to serve.
- **When you'd change it**: essentially never by hand. Your platform sets it.
  Putting it in a local `.env` silently overrides `BODYBRIDGE_PORT` on every
  run — the usual cause of "I set `BODYBRIDGE_PORT` and nothing happened".
- **If unset**: the bridge falls through to `BODYBRIDGE_PORT`, then to `8000`.
- **If invalid** (not an integer, or outside 1–65535): a warning is printed,
  the value is skipped, and the next source in the chain is tried. Not fatal.
- The port actually chosen, and which variable it came from, are printed at
  startup — check that line first when the port is not what you expected.

### `BODYBRIDGE_PORT`

- **Default**: `8000`.
- **Controls**: the TCP port to listen on, when `PORT` is not set.
- **When you'd change it**: local development, or a platform that does not
  inject `PORT`.
- **If unset**: `8000` is used silently.
- **If invalid**: a warning is printed and `8000` is used. Not fatal.

### `BODYBRIDGE_CLIENT_REGISTRATION`

- **Default**: `dcr`. Case-insensitive.
- **Controls**: how the bridge establishes who a connecting client is.
  `dcr` — Dynamic Client Registration: the client posts its `redirect_uris` to
  `/oauth/register` and gets back a self-signed `client_id`; the bridge makes
  no outbound request at all. `cimd` — Client ID Metadata Documents: the
  client's `client_id` is an `https://` URL that the bridge fetches.
- **When you'd change it**: switch to `cimd` if you specifically want the
  spec's long-term mechanism and your clients publish metadata documents the
  bridge can actually reach. `dcr` is the default because it needs no outbound
  request, which sidesteps a bot-protection challenge encountered fetching one
  real-world metadata document.
- **If unset**: `dcr` is used silently — this is a deliberate default, not an
  oversight, so no warning.
- **If invalid** (anything other than `dcr` or `cimd`): a warning is printed
  and `dcr` is used. Not fatal.

### `BODYBRIDGE_CIMD_ALLOWLIST`

- **Default**: unset — no host restriction.
- **Controls**: a comma-separated allowlist of hosts the bridge is willing to
  fetch client metadata documents from. **Only consulted in `cimd` mode**;
  under the default `dcr` mode the bridge never makes an outbound fetch, so
  this is ignored entirely.
- **When you'd change it**: to lock the bridge down to a known set of clients.
  Leaving it unset does not mean "no protection" — private, loopback,
  link-local and reserved addresses are refused regardless.
- **If unset**: no host restriction, with the address-level protections above
  still in force. No warning.
- **Invalid values**: not validated. Entries are split on commas and stripped;
  a misspelled host is simply a host that never matches, so its documents are
  refused. Nothing warns you about this, so check the spelling yourself.

### `BODYBRIDGE_TOKEN_TTL_DAYS`

- **Default**: `7`.
- **Controls**: how long an issued access token stays valid. There is no
  refresh token in V1 — once it expires the client authorizes again.
- **When you'd change it**: shorten it to reduce the window a leaked token is
  useful for; lengthen it to re-authorize less often.
- **If unset**: `7` is used silently, no warning.
- **If invalid** (not a number, or ≤ 0): a warning is printed and `7` is used.
  Not fatal.

### `BODYBRIDGE_COMMAND_TIMEOUT_SECONDS`

- **Default**: `25`.
- **Controls**: how long the bridge waits for a device to answer one command
  before giving up and returning a `timeout` result. Applies to all three
  device tools equally.
- **When you'd change it**: raise it for a device that is genuinely slow to
  act; lower it if you would rather hear back quickly that something is wrong.
- **If unset**: `25` is used silently, no warning.
- **If invalid** (not a number, or ≤ 0): a warning is printed and `25` is
  used. Not fatal.
- **Note**: a `timeout` result means the command *may or may not* have run.
  The bridge deliberately does not claim it did not.

### `BODYBRIDGE_HEARTBEAT_SECONDS`

- **Default**: `25`.
- **Controls**: how often the bridge sends a protocol-level WebSocket ping to
  a connected device. If the device misses the reply the connection is closed
  and the device is marked offline immediately.
- **When you'd change it**: lower it to detect a dropped device sooner; raise
  it to cut traffic on a metered or sleepy link.
- **If unset**: `25` is used silently, no warning.
- **If invalid** (not a number, or ≤ 0): a warning is printed and `25` is
  used. Not fatal.
- **Note**: how long the bridge then waits for the reply is a different
  setting, `ws_ping_timeout`, which uvicorn defaults to `20.0` seconds
  (`uvicorn/config.py`). The bridge does not pass a value for it, so that
  default applies, and it is not exposed as an environment variable.
- **How the two combine**: a connection is not declared dead until a ping has
  gone out *and* its 20-second reply window has elapsed. Detection therefore
  takes up to your interval plus 20 seconds. Lowering the interval does shorten
  that — what shrinks is the wait for the next ping to go out. The 20-second
  reply window is a floor, though: no interval, however small, brings detection
  below 20 seconds.

### `BODYBRIDGE_MAX_PAYLOAD_BYTES`

- **Default**: `65536` (64 KB).
- **Controls**: the largest WebSocket frame the bridge will accept from a
  device. An oversized frame closes the connection with code 1009. This is a
  hard memory guard, not a suggestion.
- **When you'd change it**: hardware varies — a Raspberry Pi can handle a
  megabyte, a small microcontroller may not. **Setting it too small is the
  dangerous direction**: if a normal result frame does not fit, the device is
  disconnected right after it connects. Around 4 KB is a sensible floor. The
  bridge does not enforce one.
- **If unset**: `65536` is used silently, no warning.
- **If invalid** (not an integer, or ≤ 0): a warning is printed and `65536` is
  used. Not fatal.

### `BODYBRIDGE_MAX_INFLIGHT`

- **Default**: `8`.
- **Controls**: how many commands may be waiting for a device reply at the
  same time. Over the limit, a send returns a `busy` result without ever
  reaching the device — which is why that result is safe to retry.
- **When you'd change it**: normal traffic is one or two in flight; the
  default is deliberately small so that a runaway loop shows up instead of
  quietly queueing. Raise it only if you have a real reason.
- **If unset**: `8` is used silently, no warning.
- **If invalid** (not an integer, or ≤ 0): a warning is printed and `8` is
  used. Not fatal.

---

## Easy to confuse

### ⚠️ `BODYBRIDGE_TOKEN` vs `BODYBRIDGE_DEVICE_TOKEN`

The names differ by one word. **The meanings are opposites.** Read this before
you flash anything.

| | `BODYBRIDGE_TOKEN` | `BODYBRIDGE_DEVICE_TOKEN` |
|---|---|---|
| What it is | The bridge's **signing key** | A **credential the device presents** |
| Who may hold it | The bridge process, and nothing else | The bridge **and** the device |
| Goes into firmware? | **Never** | Yes — this is the one that belongs in `secrets.h` |
| Leaked, it lets an attacker | Mint valid tokens for your bridge at will | Drive your device |
| Missing at startup | Refuses to start | Starts; `/device` is disabled |

**Putting `BODYBRIDGE_TOKEN` into firmware hands out the root key of the whole
authorization system.** Anyone who reads it out of the flash — and firmware is
not a secret store — can issue themselves tokens that the bridge will accept
as genuine. The device credential is the one meant to travel; the signing key
is not.

If you think you may have flashed the wrong one: rotate `BODYBRIDGE_TOKEN`
immediately. Every token already issued stops working, which is the point.

### `BODYBRIDGE_COMMAND_TIMEOUT_SECONDS` vs `BODYBRIDGE_HEARTBEAT_SECONDS`

**Both default to 25. That is a coincidence, not a relationship.** They are
independent knobs on unrelated mechanisms.

| | `COMMAND_TIMEOUT_SECONDS` | `HEARTBEAT_SECONDS` |
|---|---|---|
| Measures | One command's deadline | Interval between keepalive pings |
| Scope | A single tool call | The whole connection |
| When it fires | The device did not answer *this* command | The device stopped answering *at all* |
| Result | A `timeout` result for that call | The connection closes, device goes offline |

Changing one does not imply changing the other.

### `PORT` vs `BODYBRIDGE_PORT`

Both set the listening port. **`PORT` wins.**

Cloud platforms usually inject `PORT` themselves, so on a deployed bridge it is
already set and `BODYBRIDGE_PORT` has no effect. This is the usual explanation
for "I set the port and it did not change". The startup log prints the port
actually in use and which variable it came from — read that line before
debugging anything else.

Set `BODYBRIDGE_PORT` for local development, or on a platform that does not
inject `PORT`. Avoid putting `PORT` in a `.env` file: it will quietly take
priority every time you run locally.

### `BODYBRIDGE_MAX_PAYLOAD_BYTES` vs the internal queue limit

Both bound how much device traffic the bridge holds in memory, but they live at
different levels. `BODYBRIDGE_MAX_PAYLOAD_BYTES` is an environment variable and
caps the size of a single frame. The queue depth — how many received frames may
sit unread — is a fixed constant in `server.py` (`DEVICE_MAX_QUEUE`, 16), on the
grounds that nobody would realistically tune it.

Two honest caveats: the constant is passed to the server but the WebSocket
implementation the bridge selects **ignores it**, so today it has no effect at
all; the real protection is that the receive loop drains frames continuously.
And because it is a constant, changing it means editing the source.

---

## Firmware

The firmware has its own configuration, separate from the bridge's environment
variables. Copy `firmware/esp32-bodybridge/secrets.h.example` to `secrets.h` in
the same directory and fill it in. `secrets.h` is git-ignored and must never be
committed; the `.example` file holds only placeholders and is safe to track.

### Defined in `secrets.h`

Four placeholders you must replace:

| Macro | Placeholder | What to put there |
|---|---|---|
| `WIFI_SSID` | `"your-2.4GHz-wifi-ssid"` | Your network name. 2.4 GHz only — the classic ESP32 has no 5 GHz radio. |
| `WIFI_PASSWORD` | `"your-wifi-password"` | Your network password. |
| `BODYBRIDGE_DEVICE_TOKEN` | `"paste-your-device-token-here"` | Exactly the value of `BODYBRIDGE_DEVICE_TOKEN` on the bridge. **Not** `BODYBRIDGE_TOKEN` — see above. |
| `BRIDGE_HOST` | `"your-bridge.example.com"` | Your bridge's hostname, without scheme or path. |

Two that already hold usable defaults:

| Macro | Default | Change it when |
|---|---|---|
| `BRIDGE_PORT` | `443` | You are not using TLS, or your bridge listens elsewhere. 443 means `wss://`, which a public bridge requires. |
| `BRIDGE_PATH` | `"/device"` | Essentially never — this is the bridge's device endpoint. |

`BRIDGE_HOST` is left deliberately unreal. A plausible default would resolve to
someone else's bridge and return a puzzling 403, sending you hunting for a token
problem you do not have. An address that does not exist fails loudly with "host
not found", and one glance tells you what to fix.

### Hardcoded in the `.ino`

Six more settings live directly in `esp32-bodybridge.ino` and are **not** in
`secrets.h`. Changing any of them means editing the sketch.

| Setting | Value | What it does |
|---|---|---|
| `BODYBRIDGE_TLS_INSECURE` | `0` | **Security switch.** `0` verifies the bridge's certificate against the embedded roots. `1` skips verification — convenient for first bring-up, but anyone in the middle can then impersonate the bridge and take your device token. Never ship `1`; the compiler prints a warning on every build while it is set. |
| `LED_PIN` | `2` | The on-board LED pin, correct for most classic ESP32 boards. Different board, change this one number. |
| `RECONNECT_BASE_MS` | `1000` | Floor of the reconnect backoff, in milliseconds. |
| `RECONNECT_CAP_MS` | `30000` | Ceiling of the reconnect backoff. Between the two the delay grows exponentially with jitter. |
| Serial baud rate | `115200` | Set in `setup()`. Your serial monitor has to match it or the log is gibberish. |
| WiFi wait interval | `15000` | How often, in milliseconds, the device reports that it is still waiting to associate. |

Of these, only `BODYBRIDGE_TLS_INSECURE` and `LED_PIN` carry explanatory
comments in the source. Check the surrounding code before changing the others.
