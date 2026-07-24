# Migration guide: static token -> OAuth 2.1

This covers the change from bodybridge's original V1 auth model (a single
shared `BODYBRIDGE_TOKEN` that clients presented directly) to OAuth 2.1
authorization-code + PKCE, with short-lived JWT access tokens. Client
identity is established via Dynamic Client Registration (DCR, the default)
or Client ID Metadata Documents (CIMD, switchable) — see "Client
registration: DCR vs CIMD" below. If you deployed bodybridge before this
change, read this before you upgrade.

## What changed, in one sentence

Clients can no longer connect by presenting `BODYBRIDGE_TOKEN` directly.
They must complete an OAuth authorization flow (`/oauth/authorize` then
`/oauth/token`) to obtain a short-lived JWT, and present that JWT instead.

## New environment variables

| Variable | Required? | Default | What it's for |
|---|---|---|---|
| `BODYBRIDGE_PASSWORD` | **Yes** — the bridge refuses to start without it | none | Gates the `/oauth/authorize` consent page. This is the password *you* type when a client asks to connect. |
| `BODYBRIDGE_PUBLIC_URL` | Practically yes, for any real (non-local) deployment | falls back to `http://<host>:<port>` with a startup warning | The bridge's public HTTPS base URL. Used in OAuth discovery metadata and must match the URL you type into Claude exactly. |
| `BODYBRIDGE_TOKEN_TTL_DAYS` | No | `7` | How many days an issued access token stays valid. There's no refresh token in V1 — once it expires, the client re-authorizes. |
| `BODYBRIDGE_CLIENT_REGISTRATION` | No | `dcr` | `dcr` or `cimd` — how the bridge establishes client identity. See "Client registration: DCR vs CIMD" below. |
| `BODYBRIDGE_CIMD_ALLOWLIST` | No | unset (no restriction) | Comma-separated host allowlist for CIMD client discovery. Only relevant when `BODYBRIDGE_CLIENT_REGISTRATION=cimd`. |
| `BODYBRIDGE_COMMAND_TIMEOUT_SECONDS` | No | `25` | Bridge-side deadline (seconds) for a single device command. On timeout the bridge returns a `timeout` result saying the command may or may not have run, instead of hanging forever. Applies to all three device tools. |

See `.env.example` for the exact format of each.

## Client registration: DCR (default) vs CIMD

The bridge needs to learn who an MCP client is before showing the
`/oauth/authorize` consent page. Two mechanisms are supported, switchable
via `BODYBRIDGE_CLIENT_REGISTRATION`:

- **`dcr` (default)** — Dynamic Client Registration ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)). The client `POST`s its `redirect_uris` to `/oauth/register` and gets back a `client_id`. No outbound request from the bridge is ever made — this is why it's the default.
- **`cimd`** — Client ID Metadata Documents. The client's `client_id` is an `https://` URL that the bridge fetches to discover `redirect_uris`. This is the spec's preferred long-term mechanism, but it requires the bridge to reach out to that URL — in practice, fetching claude.ai's CIMD document (`https://claude.ai/oauth/mcp-oauth-client-metadata`) hits a Cloudflare JS challenge and returns `403`. No `User-Agent` or header change gets past this — it needs a real browser JS engine, which the bridge deliberately does not implement (no browser impersonation). That's why `dcr` is the default for now.

Both modes are fully implemented and either can be selected at any time
without any other code changes — e.g., if the Cloudflare-challenge issue
above gets resolved on Anthropic's side later, switching back to `cimd` is
just an environment variable change.

bodybridge's DCR implementation is **stateless**: no client registry is
stored anywhere. The `client_id` returned by `/oauth/register` is a
self-signed, opaque token that encodes the registered `redirect_uris` and
`client_name` directly — verified locally (no lookup, no network request)
when a client later calls `/oauth/authorize`. This is an officially
recognized pattern, not a workaround: RFC 7591 Appendix A.5.2 is titled
"Stateless Client Registration", and OpenID Connect DCR 1.0 §8.2 describes
exactly this approach ("encode necessary registration information about
the Client into the `client_id` value returned").

**Honest limitation**: because there's no client registry, there is no way
to revoke a single client's registration. The only way to invalidate a
`client_id` is to rotate `BODYBRIDGE_TOKEN` — which, same as with access
tokens (see below), invalidates *every* previously-issued `client_id`,
authorization code, and access token at once, not just the one you meant
to revoke. This is a low-stakes version of that same tradeoff though: a
`client_id` alone grants no access to anything — the `/oauth/authorize`
password gate is still the real security boundary.

## `BODYBRIDGE_TOKEN`'s meaning changed — the name did not

This is the one most likely to trip you up. `BODYBRIDGE_TOKEN` still
exists, with the same name (we don't rename environment variables on a
role change — see the project's iron rules), but **what it does is
completely different now**:

- **Before**: a static shared secret. Clients presented it directly, byte
  for byte, as the Bearer token on every request.
- **Now**: the server's own private signing secret. It is used only on
  the server side — to sign authorization codes, access tokens, and (in
  `dcr` mode, via a derived sub-key) client identities, and to verify all
  of those. It is never sent to, seen by, or used by any client. If you
  have any script or config anywhere that sends
  `Authorization: Bearer $BODYBRIDGE_TOKEN` directly to `/mcp`, it will
  now get a `401` — that's expected, not a bug. Switch it to go through
  the OAuth flow instead.

You do **not** need to change the value of an existing `BODYBRIDGE_TOKEN`
during the upgrade — reusing the same value is fine, since its only
consumer now is the bridge itself. But see the limitation below before you
ever rotate it.

## `BODYBRIDGE_HOST`'s default changed: `127.0.0.1` -> `0.0.0.0`

The bridge now listens on all network interfaces by default, not just
localhost. This is a deliberate reversal from earlier versions.

- **Why**: the bridge is meant to be reached from the outside (by claude.ai,
  by your device) — defaulting to local-only access worked against that.
  Auth is mandatory regardless of this setting (`BODYBRIDGE_TOKEN` /
  `BODYBRIDGE_PASSWORD` both refuse to start if missing), so listening
  everywhere by default exposes a locked door, not an open one.
- **Impact on you**: if you were previously relying on the old
  `127.0.0.1` default to keep the bridge local-only (for example, running
  it behind your own reverse proxy and never setting `BODYBRIDGE_HOST`
  yourself), it is now reachable from any interface after upgrading. Set
  `BODYBRIDGE_HOST=127.0.0.1` explicitly if you want the old behavior back
  — an explicit setting always overrides the default.
- If you had already set `BODYBRIDGE_HOST` yourself (to anything), nothing
  changes for you — this only affects deployments that relied on the
  unset default.

## Listening port now follows the platform's `PORT` variable first

Priority: `PORT` (the variable most cloud platforms — Heroku, Railway,
Render, Zeabur, etc. — inject to tell your app which port to listen on) >
`BODYBRIDGE_PORT` (this project's own variable) > `8000` (default).

Previously the bridge only ever read `BODYBRIDGE_PORT`, which could silently
mismatch whatever port a cloud platform actually forwarded traffic to
(the service would start successfully but be unreachable). You normally
don't need to set either variable now — the platform's own `PORT` is picked
up automatically. `BODYBRIDGE_PORT` still works if you need to pin a
specific port yourself (e.g., local development, or a platform that doesn't
inject `PORT`).

## Behavior change: how clients connect now

1. Client discovers the bridge's OAuth metadata (`/.well-known/oauth-protected-resource/mcp`, `/.well-known/oauth-authorization-server`).
2. (`dcr` mode, default) Client `POST`s to `/oauth/register` with its `redirect_uris` and gets back a `client_id`. (`cimd` mode) Client already has a `client_id` — an `https://` URL the bridge will fetch.
3. Client sends the user (you) to `/oauth/authorize` with that `client_id`, `redirect_uri`, and a PKCE `code_challenge`.
4. You enter `BODYBRIDGE_PASSWORD` on the consent page.
5. The bridge redirects back with a short-lived authorization code.
6. The client exchanges that code (plus the PKCE `code_verifier`) at `/oauth/token` for a JWT access token, valid for `BODYBRIDGE_TOKEN_TTL_DAYS` days.
7. The client presents that JWT as the Bearer token on `/mcp` requests until it expires, then repeats from step 3 (registration in step 2 typically isn't needed again — the same `client_id` keeps working).

## Honest limitation: rotating `BODYBRIDGE_TOKEN` invalidates every issued token, all at once

Access tokens are stateless, self-contained JWTs, signed with
`BODYBRIDGE_TOKEN`. There is no server-side table of "currently valid
tokens" to selectively revoke one — that's the tradeoff for not keeping
any session state. This means:

- If `BODYBRIDGE_TOKEN` leaks and you rotate it, **every** previously
  issued token stops working immediately (not just the one you meant to
  revoke) — every connected client must go through `/oauth/authorize`
  again.
- There is no way, in V1, to revoke a single token without revoking all
  of them.

If you need per-token revocation, that's a real gap to design around
later — it isn't in scope for V1.

## Internal token structure changed — no action needed

Authorization codes and access tokens used to embed the client's full
`client_id` value verbatim. Since `client_id` (especially in `dcr` mode) is
itself a self-signed blob encoding `redirect_uris` and `client_name`, this
meant a code or token's size grew with however large the client's
registration was — and the access token carries that weight on every
`/mcp` request for its whole lifetime, not just once. This version stores
a SHA-256 hash of `client_id` (a fixed 43 characters) instead, in both the
authorization code and the access token's `sub` claim. Verification is
unaffected: the bridge still confirms "the client presenting this code/token
is the same one that started the flow" — it just compares hashes instead of
full values.

**No upgrade action is needed.** This only changes the internal shape of
*newly issued* tokens going forward. Any access token issued before this
upgrade keeps working exactly as before, until it naturally expires (up to
`BODYBRIDGE_TOKEN_TTL_DAYS` days) — because the auth middleware only ever
validates a token's signature, `exp`, `aud`, and `iss`; it never reads or
checks the `sub` claim's format. An old-style token (`sub` = full
`client_id`) and a new-style token (`sub` = hash) are equally valid to the
middleware, as long as the signature checks out.

This is a different situation from rotating `BODYBRIDGE_TOKEN` (above):
rotating the signing secret breaks the *signature* itself, which is what
actually invalidates every outstanding token at once. This change never
touched the signing mechanism — only what one claim inside the token
contains — so it has no equivalent effect on already-issued tokens.

## Behavior change: `internal_error` is no longer `retryable`

This is the one **breaking** change in this version, and it's a quiet one:
nothing errors, nothing crashes, the behavior just silently shifts. Anyone
relying on the old meaning gets no warning — which is exactly why it's
written down here (iron rules 1 and 2).

- **What changed**: an `internal_error` device result now comes back with
  `retryable: false`. It used to be `retryable: true`.
- **Why**: `retryable` was redefined to answer exactly one question —
  *"is this command known for certain NOT to have reached the device?"*
  Only `offline` (a confirmed non-delivery) qualifies. An `internal_error`
  means something threw mid-flight and whether the device actually got the
  command is **unknown**, so it must not advertise itself as safe to retry.
  (This follows the general principle behind gRPC's official retry
  proposal: only statuses that indicate the server never processed the
  request should be retried; `INTERNAL`-class errors should not.)
- **What you need to do**: nothing, *unless* your Adapter or some
  upper-layer logic keyed off "`internal_error` is retryable" to auto-resend
  a command. If it did, adjust it — re-sending on `internal_error` risks
  running the command twice, because the first attempt may already have
  executed.

### New error code: `timeout` (additive, non-breaking)

This version also adds a fifth error code, `timeout`, returned by the
bridge's own per-command deadline (see `BODYBRIDGE_COMMAND_TIMEOUT_SECONDS`
above). It's purely additive — nothing that worked before breaks — but
Adapter authors should know it now exists:

- It carries `retryable: false` for the same reason as `internal_error`:
  on a timeout, whether the command reached the device is unknown, so it
  must not be blindly retried.
- The authoritative list of error codes now lives in `ErrorCode` in
  `adapters/base.py` (`offline` / `timeout` / `internal_error` /
  `unknown_command` / `bad_params`), with a picking guide in its docstring.

## Behavior change: default adapter is now ESP32Adapter (was MockAdapter)

Previous versions shipped with `MockAdapter` as the active device — a virtual
device that always answered with fake data. This version switches the default
to `ESP32Adapter`, the first real WebSocket device slot.

- **What changed**: the three device tools no longer return fake data. They
  now reflect the real connection state of a device on the `/device` endpoint.
- **Before** (mock): `get_status` → "online, battery 87"; `send_command` →
  fake success; `list_capabilities` → 3 fake capabilities.
- **Now** (ESP32, no device connected): all three return an `offline` result
  ("the device isn't connected to the bridge"). Note `list_capabilities` is
  offline too — unlike the mock's static list, ESP32Adapter asks the device
  live, so with no device there's nothing to answer.
- The `/device` endpoint changes from "always refuses" to "accepts a device
  connection" — provided you set `BODYBRIDGE_DEVICE_TOKEN` (see `.env.example`).
- **`/mcp` and OAuth are completely unaffected** — this only touches the
  device tools' return values and whether `/device` admits a connection.

**What you need to do**: nothing, unless you want to connect a device. To do
that, set `BODYBRIDGE_DEVICE_TOKEN` and flash firmware that connects to
`/device`. If you were relying on the mock's fake "online" answers for a demo,
see "Reverting to MockAdapter" below.

### Reverting to MockAdapter

There is **no environment-variable switch** for the adapter — a deliberate V1
choice (a global mode flag would collide with the per-device routing planned
for multi-device support, and changing that later would break backward
compatibility). To run the mock instead, edit `server.py`: change the
`device = ESP32Adapter(...)` line back to `device = MockAdapter()` and swap the
import back. `adapters/mock.py` is kept in the tree precisely so this one-line
change — and its role as a reference for third-party adapter authors — stays
easy.

## Upgrade checklist

1. Set `BODYBRIDGE_PASSWORD` — pick a long random value (see `.env.example`). The bridge will refuse to start without it.
2. Set `BODYBRIDGE_PUBLIC_URL` if you're running this somewhere other than localhost — it must be the exact HTTPS URL you'll type into Claude.
3. Leave `BODYBRIDGE_TOKEN` as-is (its value doesn't need to change; only its role did — see above).
4. Restart the bridge.
5. Re-add the connector in Claude (or wherever your client is configured) — it needs to go through the new OAuth flow, a previously-saved static-token config will no longer work.
6. If you had anything hardcoding `Authorization: Bearer <your old token>`, remove it — it will now be rejected.

## How to verify it actually works

`scripts/oauth_flow_check.py` drives the full chain — registration,
authorize, password check, code exchange, JWT issuance, and middleware
verification — against the real server code, without needing a real
deployment or a real external OAuth client. Run it any time you want to
confirm the OAuth plumbing still works:

```
python scripts/oauth_flow_check.py
```
