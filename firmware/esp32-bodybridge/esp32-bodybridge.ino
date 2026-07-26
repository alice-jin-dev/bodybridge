/*
 * bodybridge — ESP32 firmware (reference sample)
 *
 * Connects OUT to the bridge's /device WebSocket endpoint (wss), receives `cmd`
 * frames, runs them, and replies with `result` frames. First sample command:
 * set_led. See firmware/README.md for wiring, flashing, and the acceptance test.
 *
 * This file is a STARTING POINT, not a spec — only the frame contract is fixed
 * (README > "Adapting this for your own device": MUST / SHOULD / MAY). Rename,
 * restructure, swap libraries freely.
 *
 * Requires: ArduinoJson >= 7.3 (copy-by-default string storage — see the frame
 * section) and arduinoWebSockets (Links2004).
 */
#include <WiFi.h>
#include <WebSocketsClient.h>
#include <ArduinoJson.h>          // v7.3+ required (see sendResult note)
#include "secrets.h"             // WIFI_SSID / WIFI_PASSWORD / BODYBRIDGE_DEVICE_TOKEN / BRIDGE_*

// ---- TLS security switch (⚠️ read before flashing) ----
// 0 = verify the bridge certificate against the embedded ISRG roots (REQUIRED
//     for release; this is the safe default). 1 = skip verification (beginSSL):
//     handy for first bring-up, but a man-in-the-middle can then impersonate the
//     bridge and steal BODYBRIDGE_DEVICE_TOKEN. NEVER ship with 1 — whenever it
//     is 1 the compiler prints a #warning on every build (see startBridgeConnection).
#define BODYBRIDGE_TLS_INSECURE 0

// ---- board config ----
#define LED_PIN 2                 // On-board LED on most classic ESP32 boards.
                                 // Wrong board? change this ONE number (README).

// ---- reconnect tuning ----
static const uint32_t RECONNECT_BASE_MS = 1000;    // 1s base / floor
static const uint32_t RECONNECT_CAP_MS  = 30000;   // 30s cap

WebSocketsClient webSocket;
static uint32_t reconnectAttempt = 0;
static uint32_t lastDisconnectMs = 0;   // for the backoff-verification log

// ---- forward declarations (explicit, so .ino auto-prototyping of custom-type
//      params like JsonVariantConst / WStype_t can't trip the compiler) ----
void     connectWiFi();
void     startBridgeConnection();
void     onWsEvent(WStype_t type, uint8_t* payload, size_t length);
void     handleTextFrame(uint8_t* payload, size_t length);
void     dispatchCmd(const char* id, const char* command, JsonVariantConst params);
void     handleSetLed(const char* id, JsonVariantConst params);
void     handleGetStatus(const char* id);
void     handleListCapabilities(const char* id);
void     sendResult(const char* id, bool ok, const char* message,
                    JsonVariantConst data, const char* error, bool retryable);
void     sendError(const char* id, const char* error, const char* message, bool retryable);
void     sendSetLedOk(const char* id, bool on);
uint32_t nextBackoffMs();


// ==================== setup / connection ====================

void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("[wifi] connecting to ");
  Serial.println(WIFI_SSID);
  uint32_t startMs = millis();
  uint32_t lastNagMs = startMs;
  while (WiFi.status() != WL_CONNECTED) {
    delay(300);
    Serial.print('.');
    // Still blocking (no WiFi = no work to do), but say WHY after 15s of dots,
    // and keep saying it every 15s — so the user can tell wrong-password /
    // weak-signal / 5 GHz-SSID apart instead of staring at endless dots (rule 4).
    if (millis() - lastNagMs >= 15000) {
      lastNagMs = millis();
      Serial.printf("\n[wifi] still not connected after %us. Check SSID/password "
                    "in secrets.h; classic ESP32 is 2.4 GHz only.\n",
                    (unsigned)((millis() - startMs) / 1000));
    }
  }
  Serial.printf("\n[wifi] connected  ip=%s  rssi=%d dBm\n",
                WiFi.localIP().toString().c_str(), WiFi.RSSI());
}

// ---- TLS trust anchors (embedded root CAs) ----
// Two Let's Encrypt roots concatenated into ONE PEM string. On ESP32,
// beginSslWithCA -> WiFiClientSecure.setCACert -> mbedtls_x509_crt_parse, which
// parses multiple concatenated PEM certs from a single buffer and trusts each as
// a root. Only the ROOT is embedded; the LE intermediate (E-series) is sent by
// the server during the handshake. Dual-root = immune to a Let's Encrypt
// ECDSA/RSA chain switch. Compiled only when verification is on.
#if !BODYBRIDGE_TLS_INSECURE
static const char ROOT_CA_PEM[] =
    // ISRG Root X2 — ECDSA P-384. Root of the current LE ECDSA chain the public
    // bodybridge bridge serves. notAfter 2040-09-17; Let's Encrypt may rotate
    // operationally before ~2035 ("trusted until"). Keep in sync with:
    //   https://letsencrypt.org/certs/isrg-root-x2.pem
    R"EOF(-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----
)EOF"
    // ISRG Root X1 — RSA 4096. Fallback root: covers a LE switch to an
    // X1-terminated / RSA chain so a chain change can't lock the device out.
    // notAfter 2035-06-04. Source:
    //   https://letsencrypt.org/certs/isrgrootx1.pem
    R"EOF(-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
)EOF";
#endif

void startBridgeConnection() {
  // ===== TLS ===== (mode chosen at compile time by BODYBRIDGE_TLS_INSECURE, top of file)
#if BODYBRIDGE_TLS_INSECURE
  // INSECURE: the bridge certificate is NOT verified. A man-in-the-middle can
  // impersonate the bridge and steal BODYBRIDGE_DEVICE_TOKEN. First bring-up only.
  #warning "BODYBRIDGE_TLS_INSECURE=1: bridge certificate NOT verified -- DO NOT SHIP. Set it to 0 before release."
  webSocket.beginSSL(BRIDGE_HOST, BRIDGE_PORT, BRIDGE_PATH);
#else
  // RELEASE: verify the bridge chain against the embedded ISRG roots (ROOT_CA_PEM).
  webSocket.beginSslWithCA(BRIDGE_HOST, BRIDGE_PORT, BRIDGE_PATH, ROOT_CA_PEM);
#endif

  // ===== handshake auth: /device requires Authorization: Bearer <token> =====
  // Adjacent string-literal concatenation (token is a #define'd literal).
  webSocket.setExtraHeaders("Authorization: Bearer " BODYBRIDGE_DEVICE_TOKEN);

  webSocket.onEvent(onWsEvent);
  // Reconnect interval is injected on each DISCONNECTED event (reconnect section),
  // replacing the library's fixed default with our jittered value.
}

void setup() {
  Serial.begin(115200);
  delay(200);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);     // start dark
  connectWiFi();
  startBridgeConnection();
}


// ==================== command dispatch ====================

void onWsEvent(WStype_t type, uint8_t* payload, size_t length) {
  switch (type) {
    case WStype_CONNECTED: {
      Serial.print("[ws] connected to bridge /device");
      if (lastDisconnectMs != 0) {   // BACKOFF-VERIFICATION LOG (do not delete)
        Serial.printf("  (%u ms since last disconnect)",
                      (unsigned)(millis() - lastDisconnectMs));
      }
      Serial.println();
      reconnectAttempt = 0;          // success resets the backoff
      break;
    }
    case WStype_DISCONNECTED: {
      lastDisconnectMs = millis();
      uint32_t delayMs = nextBackoffMs();   // uses the CURRENT attempt count
      // BACKOFF-VERIFICATION LOG — DO NOT DELETE. A serial capture across a
      // bridge restart is the ONLY way to confirm the runtime unknowns:
      //   (a) does the library fire DISCONNECTED on EVERY failed retry, so
      //       `attempt` actually grows (else backoff is stuck at ~1s)?
      //   (b) does our injected interval take effect this round or one late?
      //   (c) are there fixed-interval attempts we did NOT schedule (library
      //       auto-reconnect not truly taken over)?
      // "Looks like it reconnects" is NOT proof — read attempt & delay here.
      Serial.printf("[ws] disconnected  attempt=%u  next_delay=%u ms\n",
                    (unsigned)reconnectAttempt, (unsigned)delayMs);
      webSocket.setReconnectInterval(delayMs);
      reconnectAttempt++;
      break;
    }
    case WStype_TEXT:
      handleTextFrame(payload, length);
      break;
    default:
      // PING/PONG handled by the library automatically; BIN/fragments unused.
      break;
  }
}

void handleTextFrame(uint8_t* payload, size_t length) {
  JsonDocument doc;                          // ArduinoJson v7
  DeserializationError err = deserializeJson(doc, payload, length);

  // Unknown / malformed FRAME -> IGNORE + log, never crash, never drop the
  // connection (keeps future/V2 frame types backward-compatible). DISTINCT from
  // an unknown COMMAND NAME (dispatchCmd).  [MUST]
  if (err) {
    Serial.printf("[ws] ignored a frame: bad JSON (%s)\n", err.c_str());
    return;
  }
  if (doc["v"] != 1) {
    Serial.println("[ws] ignored a frame: unsupported protocol version");
    return;
  }
  const char* type = doc["type"] | "";
  if (strcmp(type, "cmd") != 0) {
    Serial.printf("[ws] ignored a non-cmd frame: type=%s\n", type);
    return;
  }
  const char* id = doc["id"] | "";
  if (strlen(id) == 0) {
    Serial.println("[ws] ignored a cmd frame with no id");
    return;
  }
  dispatchCmd(id, doc["command"] | "", doc["params"]);
}

void dispatchCmd(const char* id, const char* command, JsonVariantConst params) {
  if      (strcmp(command, "set_led") == 0)            handleSetLed(id, params);
  else if (strcmp(command, "get_status") == 0)         handleGetStatus(id);
  else if (strcmp(command, "list_capabilities") == 0)  handleListCapabilities(id);
  else {
    // Unknown COMMAND NAME: the device DID answer, it just doesn't know this
    // command -> unknown_command, retryable=false. (Contrast: unknown FRAME is
    // silently ignored above.)  [MUST]
    sendError(id, "unknown_command",
              "This device does not know that command.", /*retryable=*/false);
  }
}

void handleSetLed(const char* id, JsonVariantConst params) {
  // SHOULD (state-style, idempotent): "set_led {on:bool}", not "led_on"/"led_off"
  //   — mirrors Matter's Attribute vs Command; a retry after a dropped reply is
  //   safe. (README > "Adapting…")
  // MUST (iron rule 3): validate PRESENCE and TYPE before use. ArduinoJson
  //   returns null for a missing key and null.is<bool>() is false, so this one
  //   check catches both "on" missing and "on" wrong-type. Worst case must be a
  //   friendly error, never a silent wrong action: "set_led {}" must NOT quietly
  //   turn the LED off and report ok — that is a lie, worse than a crash.
  if (!params["on"].is<bool>()) {
    sendError(id, "bad_params", "set_led needs a boolean param 'on'.", false);
    return;
  }
  bool on = params["on"].as<bool>();
  digitalWrite(LED_PIN, on ? HIGH : LOW);
  sendSetLedOk(id, on);
}

void handleListCapabilities(const char* id) {
  // Structured list: name / description (plain language FOR CLAUDE) / params
  // (type + required + description) / idempotent. The bridge interprets NONE of
  // this — it forwards result.data verbatim (thin bridge). idempotent is a SHOULD
  // hint the bridge never reads; omit it and nothing bridge-side changes. Only
  // business commands are listed; get_status/list_capabilities are reserved
  // protocol commands with their own MCP tools.
  JsonDocument doc;
  JsonArray caps = doc["capabilities"].to<JsonArray>();

  JsonObject c = caps.add<JsonObject>();
  c["name"] = "set_led";
  c["description"] = "Turn the LED on or off.";
  JsonObject on = c["params"]["on"].to<JsonObject>();
  on["type"] = "boolean";
  on["required"] = true;
  on["description"] = "true = LED on, false = LED off";
  c["idempotent"] = true;

  sendResult(id, /*ok=*/true, "1 command available.",
             doc["capabilities"].as<JsonVariantConst>(),   // .as<> : 7.3 proxies are non-copyable
             /*error=*/nullptr, /*retryable=*/false);
}


// ==================== frame construction ====================
// Every reply is a `result` frame: the five-field envelope echoed back with the
// SAME id. MUSTs: echo id exactly, always all five fields, JSON text. The bridge
// forwards result.data verbatim — it does not transform anything.
// String storage: with ArduinoJson >= 7.3 a non-literal `const char*` (id /
// message / error here) is stored BY COPY, so there is NO dangling-pointer
// lifetime rule to remember. (Older versions stored it by pointer — that is why
// the sketch requires >= 7.3.)

void sendResult(const char* id, bool ok, const char* message,
                JsonVariantConst data, const char* error, bool retryable) {
  JsonDocument doc;
  doc["v"]       = 1;
  doc["type"]    = "result";
  doc["id"]      = id;             // MUST: echo the cmd's id
  doc["ok"]      = ok;
  doc["message"] = message;
  doc["data"]    = data;           // null when caller passes null; else verbatim
  if (error == nullptr) doc["error"] = nullptr;
  else                  doc["error"] = error;
  doc["retryable"] = retryable;

  String out;
  serializeJson(doc, out);
  webSocket.sendTXT(out);
}

void sendError(const char* id, const char* error, const char* message,
               bool retryable) {
  sendResult(id, /*ok=*/false, message,
             JsonVariantConst(), /*error=*/error, retryable);   // data = null
}

void sendSetLedOk(const char* id, bool on) {
  JsonDocument d;
  d["on"] = on;                    // echo the new state
  sendResult(id, /*ok=*/true, on ? "LED on." : "LED off.",
             d.as<JsonVariantConst>(), /*error=*/nullptr, /*retryable=*/false);
}

void handleGetStatus(const char* id) {
  // Real device state — NOT cached/faked (mirrors the bridge's "never return
  // stale status" decision). ESP32 has no battery, so report what's genuinely
  // knowable: link quality, uptime, free memory, IP.
  JsonDocument d;
  d["online"]        = true;
  d["wifi_rssi_dbm"] = WiFi.RSSI();
  d["uptime_s"]      = (uint32_t)(millis() / 1000);
  d["free_heap"]     = ESP.getFreeHeap();
  d["ip"]            = WiFi.localIP().toString();
  sendResult(id, /*ok=*/true, "Device online.",
             d.as<JsonVariantConst>(), /*error=*/nullptr, /*retryable=*/false);
}


// ==================== reconnect: backoff + jitter ====================
// After a disconnect, wait a randomized, growing delay before retrying, so a
// bridge restart doesn't make every device reconnect in lockstep (a stampede).
// Based on AWS's "full jitter", with the floor raised from ~0 to BASE to avoid
// handing the library a 0 interval (some versions read 0 as "retry now"). Pure
// full jitter's floor is ~0 and spreads wider; ours is bounded to [BASE, window].

uint32_t nextBackoffMs() {
  uint32_t shift  = reconnectAttempt < 20 ? reconnectAttempt : 20;  // avoid overflow
  uint32_t window = RECONNECT_BASE_MS << shift;
  if (window > RECONNECT_CAP_MS) window = RECONNECT_CAP_MS;
  // esp_random() = ESP32 hardware RNG (esp_random.h, usually pulled in via
  // Arduino.h), no seeding; each device draws independently — the point of jitter.
  uint32_t span = window - RECONNECT_BASE_MS + 1;
  return RECONNECT_BASE_MS + (esp_random() % span);
}


// ==================== loop ====================

void loop() {
  webSocket.loop();   // drives the connection AND the library's timed reconnect
  // nothing else: pong is automatic, commands arrive via the onEvent callback
}
