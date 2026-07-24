# bodybridge — ESP32 firmware

Turns an ESP32 into a bodybridge device: it connects **out** to the bridge's
`/device` WebSocket endpoint, receives `cmd` frames, executes them, and replies
with `result` frames. First working sample = **Claude lights up an LED**. 🔆

This firmware is also the reference sample for third-party device authors:
implement the same three command handlers over the same frame protocol and your
device plugs into bodybridge — the bridge itself doesn't change.

> Sketch: [`esp32-bodybridge/esp32-bodybridge.ino`](esp32-bodybridge/esp32-bodybridge.ino)

---

## Hardware

- **Board**: classic ESP32 (ESP32-WROOM-32 / -DOWDQ6 core, dual-core, 520 KB
  SRAM). In Arduino IDE select **"ESP32 Dev Module"**. *Not* S3/C3 — this
  sample targets the classic ESP32.
- **LED**: a plain LED driven by `digitalWrite` (no WS2812/addressable-strip
  library involved). Default pin is **GPIO2** (the usual on-board LED on classic
  ESP32 dev boards).
  - ⚠️ **The pin is an assumption, not a confirmation.** Change `LED_PIN` at the
    top of the sketch if your board differs — it's a `#define` exactly so a
    wrong guess is a one-number fix, and so third-party boards (whose LED may be
    elsewhere) can adapt.
- **USB-to-UART driver**: install the **CP210x (Silicon Labs)** driver so the
  board enumerates as a COM port.
  - ⚠️ **Batch varies.** Some units of the same listing ship with **CH340**
    instead. Check Windows Device Manager (or `ls /dev/tty*` on macOS/Linux) and
    install whichever your board actually shows — **trust the device, not the
    product page.**

---

## Arduino IDE setup

1. **Add ESP32 board support**: Boards Manager → install "esp32 by Espressif
   Systems". (If needed, add the index URL in Preferences:
   `https://espressif.github.io/arduino-esp32/package_esp32_index.json`.)
2. **Select the board**: Tools → Board → "ESP32 Dev Module".
3. **Select the port**: Tools → Port → the COM port your board shows (see the
   driver note above).
4. **Install libraries** (Library Manager):
   - **WebSockets** by *Markus Sattler* (the `Links2004/arduinoWebSockets`
     library) — the WebSocket client; supports `wss://`, custom headers, and
     auto-replies to protocol pings with pongs.
   - **ArduinoJson** by *Benoît Blanchon* — parses incoming `cmd` frames and
     builds `result` frames.
   - `WiFi` and `WiFiClientSecure` come with the ESP32 core (no install). TLS on
     ESP32 is **mbedTLS**, not BearSSL — mind that if you copy TLS snippets
     written for ESP8266.

---

## Configure your secrets

```
cd firmware/esp32-bodybridge
cp secrets.h.example secrets.h        # or copy it in your file manager
```

Then edit `secrets.h` and fill in:

| Field | What to put |
|---|---|
| `WIFI_SSID` / `WIFI_PASSWORD` | Your **2.4 GHz** WiFi (classic ESP32 has no 5 GHz radio). |
| `BODYBRIDGE_DEVICE_TOKEN` | The device token — **must exactly match** `BODYBRIDGE_DEVICE_TOKEN` set on the bridge (see next section). |
| `BRIDGE_HOST` | Your bridge's host (e.g. `your-app.zeabur.app`). The template ships a placeholder on purpose — see the comment in the file. |

`secrets.h` is git-ignored (`**/secrets.h`) and must **never** be committed.
Only `secrets.h.example` (placeholders) is tracked.

---

## Set the matching token on the bridge

The bridge only admits a device once `BODYBRIDGE_DEVICE_TOKEN` is set on its
side too (until then `/device` is disabled — that's the minimal-exposure
default). Set it in your deployment's environment (e.g. Zeabur → Variables) to
the **same value** you put in `secrets.h`, then restart/redeploy the bridge.

> Use a long random string. If it ever leaks, rotate it on **both** the bridge
> and `secrets.h` — a leaked device token means someone can drive your device.

---

## Wiring the LED

- **On-board LED**: nothing to wire — GPIO2 is already connected on most classic
  ESP32 dev boards.
- **External LED**: `GPIO2 → 220 Ω resistor → LED anode (+)`, `LED cathode (−) →
  GND`. (Change `LED_PIN` if you use another GPIO.)

---

## Light it up (acceptance)

1. Set `BODYBRIDGE_DEVICE_TOKEN` on the bridge and in `secrets.h` (same value).
2. Flash the sketch (Upload button).
3. Open Serial Monitor at **115200 baud** — watch it join WiFi, do the TLS
   handshake, and connect to `/device`.
4. In Claude (with the bodybridge connector added):
   - `device_get_status` → should now report the device is **online** (it was
     `offline` while no device was connected).
   - `device_send_command` with `command: "set_led"`, `params: { "on": true }`
     → **the LED turns on.** 🔆 `{ "on": false }` turns it off.

---

## How it works (protocol brief)

- Connects **out** to `wss://<BRIDGE_HOST>/device` with
  `Authorization: Bearer <BODYBRIDGE_DEVICE_TOKEN>` on the handshake.
- Receives JSON text frames. For a `cmd` frame it runs the command and sends
  back a `result` frame with the same `id` and the five-field envelope
  (`ok` / `message` / `data` / `error` / `retryable`) — the bridge forwards this
  verbatim, it does not transform it.
- Implements three commands:
  - `get_status` (reserved) → real device state (WiFi RSSI, uptime, free heap, IP).
  - `list_capabilities` (reserved) → what this device can do.
  - `set_led` → `params.on` (bool) drives the LED.
- **Unknown command name** → replies `error: "unknown_command"`,
  `retryable: false` (the device answered; it just doesn't know that command).
- **Unknown / malformed *frame*** (bad JSON, wrong `v`, non-`cmd` type) →
  logged to Serial and ignored, never crashes or drops the connection (this is
  what keeps V2 frame types backward-compatible).
- **Pong**: replied automatically by the WebSocket library — no heartbeat code.
- **Reconnect**: on disconnect the device retries with exponential backoff and
  jitter (AWS full jitter, floor raised to BASE to dodge a 0-interval), so a
  bridge restart doesn't cause a reconnect stampede.

---

## TLS certificate verification (dev vs release)

The bridge is served over HTTPS, so the device connects with `wss://` (TLS).
With the arduinoWebSockets library the mode is chosen by *which begin call* you
use:

- **Development (fast, INSECURE)** — `beginSSL(host, port, path)` with no CA.
  The device does **NOT verify** the bridge's certificate. Use only to get a
  first connection working.
- **Release (verified)** — `beginSslWithCA(host, port, path, ROOT_CA)`. Embed
  the bridge's root CA; the device verifies the chain.

⚠️ **Do not ship the insecure begin call.** Without verification, any machine
that can intercept your traffic can impersonate the bridge and capture your
device token. Because this firmware is also a reference sample, the insecure
call in the sketch is flagged with a loud in-code comment — so someone copying
the code (who may never read this README) still gets warned.

For the public bodybridge bridge (any Let's Encrypt host) the root CA is
**ISRG Root X2** (ECDSA, valid through 2040); embedding **ISRG Root X1** (RSA)
as well is recommended so a Let's Encrypt chain switch doesn't lock you out.
ECDSA (X2) verification is slightly slower on ESP32 than RSA — a one-time
handshake cost.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Can't join WiFi / stuck at "connecting" | Classic ESP32 is **2.4 GHz only**. Many home routers broadcast 2.4 and 5 GHz under the *same* SSID — make sure the network behind `WIFI_SSID`/`WIFI_PASSWORD` is 2.4 GHz. |
| Serial shows "host not found" / DNS error | `BRIDGE_HOST` still a placeholder or wrong — fix it in `secrets.h`. |
| Connects then immediately drops (handshake rejected) | `BODYBRIDGE_DEVICE_TOKEN` in `secrets.h` doesn't match the bridge's value, or the bridge hasn't set it (so `/device` is disabled). |
| Claude's `device_get_status` still says `offline` | The device isn't connected — check Serial for WiFi/TLS/handshake errors above. |
| Board doesn't show up as a COM port | Wrong/missing USB-UART driver — install CP210x, or CH340 if that's your batch (Device Manager). |
| Compile error `secrets.h: No such file` | You didn't create `secrets.h` — `cp secrets.h.example secrets.h` first. |
| LED never lights but `set_led` returns ok | `LED_PIN` doesn't match your board — change the `#define` at the top of the sketch. |
