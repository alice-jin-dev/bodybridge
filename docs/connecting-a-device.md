# Connecting a device

You do **not** write an adapter, and you do **not** download anything. Your
device opens a WebSocket to the bridge, presents a token, and answers in JSON.
The bridge handles the rest.

The generic WebSocket adapter already ships inside the bridge. "Swap the
adapter to change devices" is bridge-developer language — it is not something
you need to do.

**Is this you?**

| Your device | What it takes |
|---|---|
| An ESP32 | Reference firmware exists. Flash it and fill in three values. |
| Raspberry Pi, or anything you can program | Same contract — write a small WebSocket client yourself. |
| A finished commercial product / a different protocol | See [the last section](#if-your-device-cant-speak-websocket). |

---

## What you need

1. **A deployed bridge on a public HTTPS address.** See
   [Deployment](../README.md#deployment). Plain `http://` will not do.
2. **`BODYBRIDGE_DEVICE_TOKEN` set on the bridge.** Until it is set, `/device`
   is disabled and every device is refused. See
   [Configuration](configuration.md#bodybridge_device_token).
3. **A device that can run a WebSocket client** and send JSON text frames.

> **Scope, honestly stated.** Only the ESP32 path below has been tested end to
> end. Any device that follows [the contract](#the-minimum-contract) should
> work — nothing in the bridge is ESP32-specific — but we have not run it
> ourselves. If you get another device connected, a reference implementation
> is a very welcome contribution.

---

## The short path: ESP32, end to end

Five steps. Each one links to the detail in
[`firmware/README.md`](../firmware/README.md), which is the manual for this
hardware — follow it there and come back.

1. **Pick the board and the LED.** Classic ESP32 Dev Module, on-board LED on
   GPIO2. → [Hardware](../firmware/README.md#hardware)
2. **Set up the Arduino IDE** and install the two libraries. →
   [Arduino IDE setup](../firmware/README.md#arduino-ide-setup)
3. **Generate one token and put the identical value in two places** — the
   bridge's `BODYBRIDGE_DEVICE_TOKEN`, and `secrets.h` on the device. This is
   the step people get wrong; see [When it won't connect](#when-it-wont-connect).
   → [Configure your secrets](../firmware/README.md#configure-your-secrets)
4. **Flash the sketch** and watch the serial monitor at 115200 baud. →
   [Light it up](../firmware/README.md#light-it-up-acceptance)
5. **Ask Claude to turn the LED on**: `device_send_command` with
   `command: "set_led"`, `params: { "on": true }`. 🔆

---

## Did it work?

Three checks, in order. They apply to any device, not just the ESP32.

1. **The bridge's startup log** does *not* warn that `/device` is disabled.
   If it does, `BODYBRIDGE_DEVICE_TOKEN` is not set on the bridge.
2. **The device's own log** shows the handshake completing and the connection
   staying open — not connecting and immediately dropping.
3. **`device_get_status` in Claude** reports the device, instead of `offline`.

Before any device connects, all three device tools return `offline`. That is
the correct, healthy state — the bridge is up and waiting. It does not mean
anything is misconfigured.

---

Everything below is reference material. If your ESP32 is already blinking, you
are done — read on only when you need it.

---

## The minimum contract

What your device must do, if it is not running the reference firmware.

**Handshake.** Open a WebSocket to `wss://<your-bridge>/device`, with the
header `Authorization: Bearer <BODYBRIDGE_DEVICE_TOKEN>`. Rejections are
silent by design (see below). One device at a time: a new connection replaces
the old one.

**The bridge sends you `cmd` frames** — JSON text, five fields:

```json
{"v": 1, "type": "cmd", "id": "9f2c…", "command": "set_led", "params": {"on": true}}
```

**You reply with a `result` frame** carrying the same `id`:

```json
{"v": 1, "type": "result", "id": "9f2c…", "ok": true,
 "message": "LED on", "data": null, "error": null, "retryable": false}
```

Four things are hard requirements. Get any of them wrong and the bridge
silently ignores the frame, so the command times out:

- `v` is the number `1`
- `type` is exactly `"result"`
- `id` is a non-empty string, copied verbatim from the `cmd` frame
- `ok` is a real boolean — `true`, not `"true"`

`message`, `data`, `error` and `retryable` are forgiving: missing or
wrong-typed values are filled in for you.

**Two reserved command names.** Your device must be able to answer these two,
which arrive as ordinary `cmd` frames:

- `get_status` — your real current state (battery, uptime, whatever fits)
- `list_capabilities` — what your device can do

These are the reserved names **as of this version; more may be added in future
versions.** Don't use them for your own commands.

**Two rules that keep you resilient:**

- Unknown *command* → answer with `ok: false` and `error: "unknown_command"`.
  You answered; you just don't know that command.
- Unknown or malformed *frame* → log it and ignore it. Never crash, never drop
  the connection. This is what keeps you compatible with future frame types.

**What you do not implement: heartbeats.** The bridge sends protocol-level
WebSocket pings; every mainstream client library replies with a pong on its
own. Writing application-level heartbeat code is wasted effort.

---

## When it won't connect

Almost always the token. It must match **character for character** between the
bridge's `BODYBRIDGE_DEVICE_TOKEN` and the value on the device.

⚠️ It is **not** `BODYBRIDGE_TOKEN`. Those are two different secrets for two
different jobs — mixing them up is the single most common misconfiguration.
See the comparison table in [Configuration](configuration.md).

**Why this is hard to spot:** a refused handshake is closed silently, on
purpose — a prober learns nothing about why. The cost is that you learn
nothing either. Neither side prints a reason. So work by elimination:

| What you see | What it means |
|---|---|
| Bridge startup warns `/device` is disabled | The bridge has no `BODYBRIDGE_DEVICE_TOKEN`. Set it and restart. |
| Device connects, then drops immediately | Handshake refused — the tokens don't match. |
| Device never reaches the bridge (DNS, TLS, timeout) | Not a token problem. Check the host address and the network. |
| Connected, but commands time out | The connection is fine; your `result` frames are being ignored. Re-check the [four hard requirements](#the-minimum-contract). |

When the tokens don't match, re-set **both** sides from a freshly generated
value rather than hunting for the typo, then restart the bridge and re-flash
the device. A trailing space or a truncated paste looks identical to a correct
token.

For ESP32-specific symptoms — WiFi, drivers, TLS, the LED pin — see
[Troubleshooting](../firmware/README.md#troubleshooting).

If the token ever leaks, rotate it on both sides: whoever has it can drive
your device.

---

## If your device can't speak WebSocket

If it can't be programmed or reprogrammed — a finished commercial product, or
hardware that only speaks its own protocol — then this document doesn't cover
it. That case needs an adapter written on the bridge side, which is a
different job: this document is about making your device speak the bridge's
language, while an adapter makes the bridge speak your device's. A guide for
writing one is planned.
