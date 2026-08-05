# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - YYYY-MM-DD

First release. No version was published before this one, so nothing is missing
from this file — the *Changed*, *Removed* and *Fixed* entries below do **not**
refer to an earlier release. They describe how 1.0.0 differs from the untagged
development-period commits that some self-hosted deployments are already
running from git. If yours is one of those, [MIGRATION.md](MIGRATION.md) is the
step-by-step version of the same information.

### Added

- **MCP tools.** `ping`, `device_list_capabilities`, `device_get_status` and
  `device_send_command`, served over streamable-http.
- **Uniform result envelope.** Every device tool returns the same five keys —
  `ok`, `message`, `data`, `error`, `retryable` — on success and on failure
  alike, so a caller never has to branch on shape.
- **Error codes.** `offline`, `busy`, `timeout`, `internal_error`,
  `unknown_command`, `bad_params`. A device-level failure comes back as
  `ok: false`, not as an MCP protocol error.
- **OAuth 2.1 authorization.** Authorization-code flow with PKCE, a
  password-gated consent page at `/oauth/authorize`, a token endpoint at
  `/oauth/token`, and RFC 9728 / RFC 8414 discovery metadata. Access tokens
  are self-contained JWTs; the bridge keeps no session, code or token table.
- **Client registration, two modes.** Dynamic Client Registration (RFC 7591)
  is the default and makes no outbound request. Client ID Metadata Documents
  (CIMD) can be selected with `BODYBRIDGE_CLIENT_REGISTRATION=cimd`.
- **Device endpoint.** A `/device` WebSocket endpoint that a device connects
  *to*, guarded by three refusal gates (adapter capability, device token
  configured, Bearer match). Refusals are logged server-side.
- **Generic device protocol.** Versioned JSON frames (`v: 1`) over WebSocket.
  Any device that can open a WebSocket speaks it — no adapter to write and
  nothing to install on the device side.
- **Single-connection ownership.** A new device connection replaces the old
  one, and the displaced connection's later teardown cannot clear the new one.
- **ESP32 reference firmware** under `firmware/`, verifying the bridge's
  certificate against embedded ISRG roots.
- **Configuration.** `BODYBRIDGE_TOKEN`, `BODYBRIDGE_PASSWORD` and
  `BODYBRIDGE_PUBLIC_URL` are required. Optional: `BODYBRIDGE_HOST`,
  `BODYBRIDGE_PORT`, `BODYBRIDGE_CLIENT_REGISTRATION`,
  `BODYBRIDGE_CIMD_ALLOWLIST`, `BODYBRIDGE_TOKEN_TTL_DAYS`,
  `BODYBRIDGE_COMMAND_TIMEOUT_SECONDS`, `BODYBRIDGE_DEVICE_TOKEN`,
  `BODYBRIDGE_HEARTBEAT_SECONDS`, `BODYBRIDGE_MAX_PAYLOAD_BYTES`,
  `BODYBRIDGE_MAX_INFLIGHT`. A platform-injected `PORT` takes precedence over
  `BODYBRIDGE_PORT`.
- **Bridge-side deadline.** A command that gets no device reply within
  `BODYBRIDGE_COMMAND_TIMEOUT_SECONDS` (default 25) returns `timeout` rather
  than hanging. The message says the command may or may not have run, because
  that is what the bridge actually knows.
- **Back-pressure.** More than `BODYBRIDGE_MAX_INFLIGHT` commands awaiting a
  device result returns a retryable `busy`.
- **Heartbeat.** The bridge pings the device every
  `BODYBRIDGE_HEARTBEAT_SECONDS`; a missed pong closes the connection and the
  device is marked offline immediately.
- **Documentation.** [Configuration reference](docs/configuration.md),
  [Connecting a device](docs/connecting-a-device.md),
  [Deployment](docs/deployment.md), [MIGRATION.md](MIGRATION.md) and
  [SECURITY.md](SECURITY.md).

### Changed

- **`BODYBRIDGE_TOKEN` means something different.** It is now the server's own
  JWT signing secret, never handed to a client. It is no longer a shared
  password that clients present.
- **`BODYBRIDGE_HOST` defaults to `0.0.0.0`** (was `127.0.0.1`). The bridge is
  meant to be reachable from outside, and it refuses to start without
  authentication configured. Set `127.0.0.1` explicitly for local-only access.
- **The platform's `PORT` wins.** Precedence is `PORT` > `BODYBRIDGE_PORT` >
  `8000`. Setting `PORT` in a local `.env` silently overrides
  `BODYBRIDGE_PORT`.
- **`BODYBRIDGE_PUBLIC_URL` is required.** Previously it fell back to
  `http://127.0.0.1:8000` with a warning; the bridge now exits 1 when it is
  unset. Every OAuth metadata field and the `iss`/`aud` of every issued token
  derive from it, so on a public deployment the old fallback made all of them
  wrong at once, silently. A value that *is* set but malformed still falls
  back with a warning — only missing is fatal.
- **The default adapter drives a real device.** `WebSocketAdapter` replaces
  `MockAdapter`, so the three device tools report real connection state
  instead of fake data. With no device connected they return `offline` —
  including `list_capabilities`, which asks the device rather than serving a
  static list. `adapters/mock.py` remains in the tree and can be selected by
  editing one line in `server.py`.
- **`internal_error` is no longer `retryable`.** An unexpected internal fault
  is not something a caller should retry into.
- **`ESP32Adapter` is now `WebSocketAdapter`**, and `adapters/esp32.py` is now
  `adapters/websocket.py`. Behaviour is unchanged. The class never held
  ESP32-specific logic; ESP32 remains the reference firmware. This only
  affects forks that import the class directly.
- **`.env` is loaded automatically** at startup, so no `--env-file` flag is
  needed for a local run.

### Removed

- **Static-token authentication.** Presenting the raw `BODYBRIDGE_TOKEN` as a
  Bearer credential is rejected. Clients obtain a JWT through the OAuth flow.

### Fixed

- OAuth parameters are read from the query string on an `/oauth/authorize`
  POST, not only from the body.
- The local fallback base URL uses a loopback address instead of `0.0.0.0`,
  which is a bind target and not a reachable address.

### Security

- **Authentication is mandatory.** The bridge exits 1 rather than start
  without `BODYBRIDGE_TOKEN` or `BODYBRIDGE_PASSWORD`, instead of starting up
  open or with OAuth silently broken.
- **Every request is verified.** Transport is stateless, so each MCP call
  carries and re-verifies its own token — signature, `exp`, `aud` and `iss`
  are all checked explicitly. Authorization is not granted once at handshake
  time.
- **Audience binding.** An issued token is bound to this bridge's own
  resource; a token request naming a different resource is rejected with
  RFC 8707 `invalid_target`.
- **Only one signing algorithm.** HS256 is specified explicitly when signing
  and when verifying, so a token cannot select its own algorithm.
- **SSRF hardening on CIMD fetches.** Private, loopback, link-local and
  reserved addresses are refused; DNS is pinned between resolution and
  connection; the response body is size-capped. `BODYBRIDGE_CIMD_ALLOWLIST`
  narrows it further to named hosts. Under the default `dcr` mode no outbound
  fetch happens at all.
- **The device endpoint is closed by default.** Without
  `BODYBRIDGE_DEVICE_TOKEN` the `/device` endpoint admits nobody; the bridge
  starts anyway and says so. Refused handshakes are logged server-side.
- **Frame-size guard.** Device frames larger than
  `BODYBRIDGE_MAX_PAYLOAD_BYTES` (default 64 KB) close the connection with
  code 1009.
- **Firmware verifies TLS.** The ESP32 reference firmware checks the bridge's
  certificate chain against embedded ISRG roots.
- **Authorization responses carry `iss`** (RFC 9207), on error responses as
  well as successful ones.
- **Consent page hardening.** `X-Frame-Options: DENY` and `Cache-Control:
  no-store` on the authorization and registration responses.
- **Documented non-goals.** [SECURITY.md](SECURITY.md) states what this
  version deliberately does not defend against, rather than implying complete
  coverage.

[1.0.0]: https://github.com/alice-jin-dev/bodybridge/releases/tag/v1.0.0
