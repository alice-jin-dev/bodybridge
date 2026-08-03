# Deployment

How to put the bridge on a public address so an MCP client can reach it.

This page covers the deployment itself: what the bridge needs from a host, how
to bring it up, and how to tell whether it worked. It does not re-explain the
settings — for what each environment variable means and how it fails, see the
[configuration reference](configuration.md). Once the bridge is up and you want
to attach real hardware, continue to [Connecting a device](connecting-a-device.md).

If you are upgrading an existing deployment rather than making a new one, read
[MIGRATION.md](../MIGRATION.md) first — authentication changed from a static
token to OAuth 2.1.

---

## The short path

1. Have the three required values ready — [Before you start](#before-you-start)
2. Deploy to a host with a public HTTPS address — [what a host must
   provide](#what-the-bridge-needs-from-a-host)
3. Set the three variables in the platform's variables panel — [worked
   example](#one-worked-example-zeabur)
4. Collect the assigned domain, set `BODYBRIDGE_PUBLIC_URL` to it, restart —
   [worked example](#one-worked-example-zeabur)
5. Run the three checks, then add the bridge to your MCP client — [three
   checks](#three-read-only-checks)

---

## Before you start

You need three values ready. All three are mandatory: the bridge checks them in
order at startup and exits with status 1 on the first one missing, without
checking the rest.

| Variable | What you put in it |
|---|---|
| `BODYBRIDGE_TOKEN` | A long random secret. Server-side only — never goes into firmware. |
| `BODYBRIDGE_PASSWORD` | A long random secret, different from the one above. You type it by hand on the consent page. |
| `BODYBRIDGE_PUBLIC_URL` | The bridge's public base URL. Not a secret. |

Full descriptions, generation commands, and the exact failure behavior of each:
[Configuration → Required](configuration.md#required).

### The one that catches people

**`BODYBRIDGE_PUBLIC_URL` must match, character for character, the URL you type
into your MCP client when adding the connector** — scheme, host, port, path, and
trailing slash all included.

This is not a cosmetic setting. Every field of the OAuth discovery metadata, and
the `iss` and `aud` claims of every token the bridge signs, are derived from this
one string. If it disagrees with what the client believes the address is,
resource validation fails and the connection is rejected — even though the bridge
is running, serving, and logging nothing unusual.

Write it with no trailing slash and no `/mcp` path. The bridge appends `/mcp`
itself.

There is an ordering problem here, and it is worth knowing in advance: on most
hosting platforms the domain is only assigned *after* the first deployment
finishes. So the sequence is deploy → collect the domain → set
`BODYBRIDGE_PUBLIC_URL` → restart. Expect to start the bridge twice.

---

## What the bridge needs from a host

**The bridge is not tied to any platform, and this project does not maintain a
list of supported ones.** Where you run it is a prerequisite you bring yourself,
the same way you bring a Python interpreter. bodybridge is an ordinary Python
process; anything that can run one and expose it to the internet will do.

What that environment has to provide:

- **A public address, reachable in both directions.** Your AI client's servers
  perform OAuth discovery against the bridge from the outside; your device opens
  its own connection to the bridge from wherever it happens to live. An address
  that only resolves on your LAN or behind a VPN fails the first. A host your
  device cannot route to fails the second. Both have to hold, and they are two
  different networks.
- **HTTPS with a certificate a public client will trust.** Self-signed
  certificates do not work here. In practice the platform terminates TLS for
  you; the bridge itself speaks plain HTTP behind it.
- **WebSocket support on long-lived connections.** The device layer holds an
  open WebSocket at `/device` for as long as the device is powered on. A host
  that proxies HTTP but drops or refuses WebSocket upgrades will run the bridge
  fine and never let a device stay connected. If you are not attaching hardware
  yet, this one can wait — but check it before you buy anything.
- **A way to set environment variables.** Set them in the platform's own
  configuration panel, not in a `.env` file. The bridge loads a neighboring
  `.env` for local development, but variables already present in the environment
  are never overwritten by it — a platform-injected value always wins.
- **Python 3.10 or newer**, and a way to install dependencies (this project uses
  `uv`).

Because that first requirement has to hold in *both* directions, **where** you
deploy is a real decision rather than a default. One region may reach your AI
client's servers comfortably while sitting far from your device, or the reverse;
the two are not automatically satisfied by the same choice. Pick a region
appropriate for your own network environment, and check both directions before
you commit to it.

Network quality is a separate axis from reachability, and V1 is forgiving on
it: motion control is latency-tolerant, so most networks are fine.

You usually do **not** need to configure a port. The bridge reads the platform's
injected `PORT` variable first, falls back to `BODYBRIDGE_PORT`, then to `8000`,
and it binds `0.0.0.0` by default. On a platform that injects `PORT`, setting
`BODYBRIDGE_PORT` has no effect at all — see
[`PORT` vs `BODYBRIDGE_PORT`](configuration.md#port-vs-bodybridge_port).

### There are no platform config files in this repository

You will not find a `Procfile`, a `Dockerfile`, a `zeabur.json`, or any other
platform descriptor here, and none is missing. The repository holds a Python
project and nothing else; the deployment shape lives on the platform's side.

Stated honestly: that is a conclusion from the one platform this has actually
been run on. A different host may well want a build file, a start command, or a
container definition. Check your platform's own documentation — if it needs one,
writing it is a normal part of deploying there, not a gap in this project.

---

## One worked example: Zeabur

This is the deployment we actually run. It is written down because it has been
verified end to end, **not as a recommendation** — nothing about the bridge
prefers this platform, and the same five moves apply anywhere.

1. **Point the platform at the repository.** No build configuration to write; it
   is a standard Python project.
2. **Set the three required variables** in the platform's variables panel:
   `BODYBRIDGE_TOKEN`, `BODYBRIDGE_PASSWORD`, `BODYBRIDGE_PUBLIC_URL`. If you do
   not have the domain yet, put a placeholder in the third one — the bridge will
   start, and everything OAuth-related will be wrong until you fix it. It is
   equally fine to leave it empty, accept the refused startup, and fill it in on
   the next step.
3. **Collect the assigned domain, then set `BODYBRIDGE_PUBLIC_URL` to it** — for
   example `https://your-bridge.zeabur.app`, no trailing slash, no `/mcp` — and
   restart so the new value is picked up.
4. **Read the startup log.** On a successful start the bridge prints, to stderr:

   ```
   [bodybridge] starting on 0.0.0.0:8080 (port source: PORT)
   [bodybridge] client registration mode: dcr
   ```

   The port number is whatever the platform injected; `port source` tells you
   which variable it came from (`PORT`, `BODYBRIDGE_PORT`, or `default`). Read
   that line before debugging anything port-related.

   You will probably also see this, and it is expected:

   ```
   [bodybridge] warning: /device is disabled because BODYBRIDGE_DEVICE_TOKEN is not set.
     The device layer is active but no device can connect until you set it.
   ```

   The bridge is up; only the device endpoint is off. Set
   [`BODYBRIDGE_DEVICE_TOKEN`](configuration.md#bodybridge_device_token) when you
   are ready to attach hardware.

5. **Run the three checks below**, then add the bridge to your MCP client.

---

## Three read-only checks

All three are plain GETs. None of them changes anything, and none of them needs
a token.

**1. Protected-resource metadata — expect `200`.**

```sh
curl -i https://your-bridge.example.com/.well-known/oauth-protected-resource/mcp
```

Returns JSON containing `resource` and `authorization_servers`.

**2. Authorization-server metadata — expect `200`.**

```sh
curl -i https://your-bridge.example.com/.well-known/oauth-authorization-server
```

Returns JSON containing `issuer`, `authorization_endpoint`, and
`token_endpoint`.

> **Read the values, not just the status code.** Every URL in these two
> documents is built from `BODYBRIDGE_PUBLIC_URL`. If the `resource`, `issuer`,
> or endpoint URLs come back as anything other than the address you just typed
> into `curl`, then `BODYBRIDGE_PUBLIC_URL` is wrong or was never picked up, and
> no client will be able to complete the OAuth flow. A `200` alone does not
> prove this is configured correctly.
>
> The giveaway is a local `http://` address where you expected your public
> `https://` one. That is the bridge's built-in fallback, assembled from the
> host and port it actually bound — not from anything you configured.

**3. The MCP endpoint without a token — expect `401`.**

```sh
curl -i https://your-bridge.example.com/mcp
```

A `401` here is the correct answer, not a failure. The response carries a
`WWW-Authenticate: Bearer resource_metadata="…"` header pointing back at check
1, which is how a client discovers where to authenticate, and a JSON body saying
plainly that no `Authorization` header was sent.

Note what this check does and does not prove: the `401` comes from the auth
middleware, which rejects every path outside the public OAuth prefixes. It
confirms that authentication is switched on and that the discovery pointer is
correct. It does not by itself prove the MCP handler behind it is healthy — the
client connecting successfully is what proves that.

If all three behave as described, the bridge is deployed. Add it to your MCP
client using exactly the URL from check 3, including the `/mcp` path.

---

## After it's deployed

### Changing a setting

Every environment variable is read once, when the process starts. Changing one
in the platform's panel does nothing until the bridge restarts — and this holds
for all of them, not just `BODYBRIDGE_PUBLIC_URL`. Restart from the platform's
own controls; how to trigger one is in your platform's documentation.

### Upgrading to a new version

Update your copy of the repository to the new version, then redeploy. On most
platforms that means pushing to the branch the deployment tracks, or triggering
a rebuild from its dashboard — follow your platform's documentation for the
exact action.

Check [MIGRATION.md](../MIGRATION.md) before you do: breaking changes and the
steps they require are recorded there.

### Reading the logs

The bridge's own output — startup lines, warnings, and refusal notices alike —
goes to **stderr**. Uvicorn, the server underneath it, writes its own lines
too. The bridge keeps no log file of its own, so on a cloud platform the
platform's log panel is where all of it shows up.

Two things worth knowing before you go looking:

- The startup lines (`starting on …`, `client registration mode: …`) are
  printed **once**, at boot. If the platform's log view has rolled over since
  then, they are no longer there — restart the bridge to see them again.
- Refusals at the `/device` endpoint are logged one line each, at the moment
  they happen. That means "why won't my device connect" stays answerable from
  the log after the fact, not only in the seconds around startup.

---

## When it doesn't work

### The process exits immediately, status 1

One of the three required variables is empty. The bridge checks them in a fixed
order and stops at the first failure, so you may have to fix them one at a time:

1. `BODYBRIDGE_TOKEN`
2. `BODYBRIDGE_PASSWORD`
3. `BODYBRIDGE_PUBLIC_URL`

Each refusal prints a `fatal:` line naming the variable and why it is required.
Whitespace-only counts as unset — the values are stripped before the check. See
[Configuration → Required](configuration.md#required).

Note the asymmetry on the third one: *missing* is fatal, but *malformed* is not.
A `BODYBRIDGE_PUBLIC_URL` that does not start with `http://` or `https://` only
produces a warning; the bridge falls back to a local address and starts anyway.
That is the case where everything looks healthy and nothing works — which is
what check 2 above is for.

### It starts, but the client won't connect

Assume `BODYBRIDGE_PUBLIC_URL` is the problem until proven otherwise. Compare it
against the URL in your client, character by character: scheme (`http` vs
`https`), host, port, trailing slash, and whether `/mcp` ended up in the variable
by mistake. The variable must not contain `/mcp`; the URL you give the client
must.

Then run check 2 and confirm the `issuer` in the response is the address you
expect. A mismatch there is a mismatch in every token the bridge signs.

### It won't bind a port

Uvicorn prints the address and port it is actually listening on when it starts,
and prints the bind error if it cannot. Read that against the bridge's own
`starting on HOST:PORT (port source: …)` line — together they tell you what the
bridge asked for and what actually happened.

`BODYBRIDGE_HOST` is the one variable with no validation and no fallback: an
address that cannot be bound raises an error at startup rather than falling back
to a default. On a cloud platform you normally leave it alone. See
[`BODYBRIDGE_HOST`](configuration.md#bodybridge_host).

If the port is not the one you set, you almost certainly set `BODYBRIDGE_PORT`
on a platform that injects `PORT`. The `port source` field in the startup line
names the winner.

---

## Optional: hardening at the platform level

**The bridge's own security does not depend on anything in this section.**
Authentication is enforced on every request, tokens are verified for signature,
expiry, audience, and issuer, and the device endpoint refuses connections
without its own credential. What follows is extra depth available to you as the
person who controls the hosting environment. Skipping all of it leaves the
bridge exactly as secure as it was designed to be.

If your platform offers these controls and you want to use them, they are worth
knowing about:

- **Inbound IP allowlisting.** If you know which addresses ever legitimately
  reach the bridge, you may consider restricting inbound traffic to them at the
  platform's firewall or edge. Be aware that this is only workable when those
  addresses are stable and known — an MCP client's servers and your device's
  network may not qualify, and an allowlist that is too tight simply takes the
  bridge offline for you.
- **Restricting outbound traffic.** The bridge's own code makes exactly one
  kind of outbound request: in `cimd` client-registration mode it fetches the
  client's metadata document. On the default `dcr` setting it makes none — the
  client posts to the bridge instead. If your platform supports egress rules,
  you may consider blocking outbound traffic that your configuration does not
  need.
  <!-- Maintainers: "The bridge's own code" at the start of this bullet is a
       scope limiter, and it is the premise the whole claim rests on. The
       outbound audit behind it covered first-party code only (server.py,
       oauth_cimd.py, adapters/*.py); the source of third-party dependencies
       (mcp SDK / FastMCP, starlette, uvicorn, PyJWT, python-dotenv) was not
       read. Drop the limiter and this sentence reverts to an unverified
       negative assertion about the whole process.
       Evidence: oauth_cimd.py:205 / 238 → fetch_cimd_document is the only
       outbound path (httpcore.ConnectionPool; the socket calls at :128 and
       :188 belong to the same chain). server.py:823 → its only caller, inside
       the cimd branch. oauth_cimd.py:508-511 → the pre-existing note in the
       code that DCR needs no outbound request at all. -->

Both of these are ordinary platform-side measures, not compensations for
anything in the bridge. How much they buy you depends entirely on your
environment, and neither one changes how the bridge behaves.
