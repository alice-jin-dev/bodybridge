# Migration guide: static token -> OAuth 2.1

This covers the change from bodybridge's original V1 auth model (a single
shared `BODYBRIDGE_TOKEN` that clients presented directly) to OAuth 2.1
authorization-code + PKCE + CIMD, with short-lived JWT access tokens. If
you deployed bodybridge before this change, read this before you upgrade.

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
| `BODYBRIDGE_CIMD_ALLOWLIST` | No | unset (no restriction) | Comma-separated host allowlist for CIMD client discovery, if you want to lock the bridge down to specific known clients. |

See `.env.example` for the exact format of each.

## `BODYBRIDGE_TOKEN`'s meaning changed — the name did not

This is the one most likely to trip you up. `BODYBRIDGE_TOKEN` still
exists, with the same name (we don't rename environment variables on a
role change — see the project's iron rules), but **what it does is
completely different now**:

- **Before**: a static shared secret. Clients presented it directly, byte
  for byte, as the Bearer token on every request.
- **Now**: the server's own private JWT signing key. It is used only on
  the server side — to sign tokens at `/oauth/token` and verify them in
  the auth middleware. It is never sent to, seen by, or used by any
  client. If you have any script or config anywhere that sends
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
2. Client sends the user (you) to `/oauth/authorize` with a CIMD `client_id`, `redirect_uri`, and a PKCE `code_challenge`.
3. You enter `BODYBRIDGE_PASSWORD` on the consent page.
4. The bridge redirects back with a short-lived authorization code.
5. The client exchanges that code (plus the PKCE `code_verifier`) at `/oauth/token` for a JWT access token, valid for `BODYBRIDGE_TOKEN_TTL_DAYS` days.
6. The client presents that JWT as the Bearer token on `/mcp` requests until it expires, then repeats from step 2.

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

## Upgrade checklist

1. Set `BODYBRIDGE_PASSWORD` — pick a long random value (see `.env.example`). The bridge will refuse to start without it.
2. Set `BODYBRIDGE_PUBLIC_URL` if you're running this somewhere other than localhost — it must be the exact HTTPS URL you'll type into Claude.
3. Leave `BODYBRIDGE_TOKEN` as-is (its value doesn't need to change; only its role did — see above).
4. Restart the bridge.
5. Re-add the connector in Claude (or wherever your client is configured) — it needs to go through the new OAuth flow, a previously-saved static-token config will no longer work.
6. If you had anything hardcoding `Authorization: Bearer <your old token>`, remove it — it will now be rejected.

## How to verify it actually works

`scripts/oauth_flow_check.py` drives the full chain — authorize, password
check, code exchange, JWT issuance, and middleware verification — against
the real server code, without needing a real deployment or a real external
OAuth client. Run it any time you want to confirm the OAuth plumbing still
works:

```
python scripts/oauth_flow_check.py
```
