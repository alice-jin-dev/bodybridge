"""Manual regression check for the full OAuth chain: /oauth/register ->
/oauth/authorize -> /oauth/token -> a Bearer JWT that the auth middleware
accepts on /mcp.

Run it any time after touching server.py or oauth_cimd.py:

    python scripts/oauth_flow_check.py

What this does and does not cover
----------------------------------
This drives the REAL server.py route functions and the REAL
BearerAuthMiddleware directly (constructed ASGI Request/scope objects, no
network socket involved -- so it never binds a port and can't collide with
a real bridge you might have running).

Default client registration mode is DCR (BODYBRIDGE_CLIENT_REGISTRATION
unset -> "dcr"), so this script registers a real client via the real
/oauth/register route and gets back a real, self-signed client_id -- no
network fetch, no stubbing needed at all for that step. This is different
from before this project switched to DCR: the CIMD path used to require
stubbing oauth_cimd.fetch_cimd_document, since the bridge's own SSRF guard
correctly refuses to fetch documents from loopback/private addresses (no
way to self-host a real CIMD document on localhost). That CIMD path is
still fully present and switchable via BODYBRIDGE_CLIENT_REGISTRATION=cimd,
but this script exercises the default (dcr) path since that's what actually
ships to users now.

Exit code is 0 if every check passes, 1 otherwise. Output is pure ASCII.
"""
import asyncio
import hashlib
import base64
import json
import os
import re
import sys
from urllib.parse import unquote, urlencode

sys.stdout.reconfigure(encoding="utf-8")

# Fresh, throwaway secrets for this run only -- never reused, never written
# anywhere. BODYBRIDGE_PUBLIC_URL is left unset on purpose so the bridge
# falls back to its local default, matching a typical local dev run.
os.environ["BODYBRIDGE_TOKEN"] = "oauth-flow-check-" + os.urandom(16).hex()
os.environ["BODYBRIDGE_PASSWORD"] = "oauth-flow-check-" + os.urandom(16).hex()
os.environ.pop("BODYBRIDGE_PUBLIC_URL", None)
os.environ.pop("BODYBRIDGE_CLIENT_REGISTRATION", None)  # use the default: dcr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402
from starlette.requests import Request  # noqa: E402

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def run(coro):
    return asyncio.run(coro)


def make_get(path: str, query: dict) -> Request:
    scope = {
        "type": "http", "method": "GET", "path": path,
        "query_string": urlencode(query).encode(), "headers": [],
        "client": ("127.0.0.1", 12345),
    }
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    return Request(scope, receive)


def make_post_form(path: str, form: dict) -> Request:
    body = urlencode(form).encode()
    return _make_post_raw(path, body, b"application/x-www-form-urlencoded")


def make_post_json(path: str, obj: dict) -> Request:
    body = json.dumps(obj).encode()
    return _make_post_raw(path, body, b"application/json")


def _make_post_raw(path: str, body: bytes, content_type: bytes) -> Request:
    scope = {
        "type": "http", "method": "POST", "path": path,
        "query_string": b"",
        "headers": [
            (b"content-type", content_type),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": ("127.0.0.1", 12345),
    }
    sent = {"done": False}
    async def receive():
        if not sent["done"]:
            sent["done"] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}
    return Request(scope, receive)


async def drive_middleware(auth_header_value: str | None):
    """Runs the real BearerAuthMiddleware for a request to /mcp. Returns
    (downstream_called, response_status_if_rejected, response_headers)."""
    headers = []
    if auth_header_value is not None:
        headers.append((b"authorization", auth_header_value.encode("latin-1")))
    scope = {"type": "http", "method": "GET", "path": "/mcp", "headers": headers}

    downstream_called = {"yes": False}

    async def downstream_app(scope, receive, send):
        downstream_called["yes"] = True

    result = {"status": None, "headers": {}}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            result["status"] = message["status"]
            result["headers"] = {
                k.decode("latin-1").lower(): v.decode("latin-1")
                for k, v in message.get("headers", [])
            }

    mw = server.BearerAuthMiddleware(downstream_app, token=server.TOKEN)
    await mw(scope, receive, send)
    return downstream_called["yes"], result["status"], result["headers"]


check("default client registration mode is dcr", server.CLIENT_REGISTRATION == "dcr",
      server.CLIENT_REGISTRATION)

# --- Step 1: register a client via the real /oauth/register route ----------

REDIRECT_URI = "https://oauth-flow-check.example/callback"  # TEST FIXTURE, not a real URL

resp = run(server.oauth_register(make_post_json("/oauth/register", {
    "redirect_uris": [REDIRECT_URI], "client_name": "oauth_flow_check test client",
})))
check("POST /oauth/register -> 201", resp.status_code == 201, f"got {resp.status_code}: {resp.body}")
CLIENT_ID = json.loads(resp.body).get("client_id") if resp.status_code == 201 else None
check("registration returned a client_id", bool(CLIENT_ID))

# --- Step 2: obtain a real code via the real /oauth/authorize route --------

verifier = base64.urlsafe_b64encode(os.urandom(48)).rstrip(b"=").decode("ascii")
challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
authorize_params = {
    "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
    "state": "flow-check-state", "code_challenge": challenge,
    "code_challenge_method": "S256",
}

resp = run(server.oauth_authorize(make_get("/oauth/authorize", authorize_params)))
check("GET /oauth/authorize renders the password form", resp.status_code == 200,
      f"got {resp.status_code}")

resp = run(server.oauth_authorize(make_post_form("/oauth/authorize", {
    **authorize_params, "password": os.environ["BODYBRIDGE_PASSWORD"],
})))
check("POST /oauth/authorize with the correct password -> 302", resp.status_code == 302,
      f"got {resp.status_code}: {resp.body}")
m = re.search(r"[?&]code=([^&]+)", resp.headers.get("location", ""))
check("authorization code present in the redirect", m is not None)
code = unquote(m.group(1)) if m else None

# --- Step 3: exchange the code for a JWT via the real /oauth/token route ---

resp = run(server.oauth_token(make_post_form("/oauth/token", {
    "grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI, "code_verifier": verifier,
})))
check("POST /oauth/token exchanges the code for a JWT", resp.status_code == 200,
      f"got {resp.status_code}: {resp.body}")
token_body = json.loads(resp.body) if resp.status_code == 200 else {}
access_token = token_body.get("access_token")
check("response contains access_token", bool(access_token))

# --- Step 4: use the JWT against the real BearerAuthMiddleware on /mcp -----

called, status, headers = run(drive_middleware(f"Bearer {access_token}"))
check("valid JWT -> middleware lets the request through to /mcp", called,
      f"downstream called={called}, status={status}")

# --- Regression / security checks ------------------------------------------

called, status, headers = run(drive_middleware(None))
check("no Authorization header -> rejected with 401", (not called) and status == 401)
check("no Authorization header -> WWW-Authenticate present",
      "www-authenticate" in headers, headers)

called, status, _ = run(drive_middleware(f"Bearer {server.TOKEN}"))
check("RETIRED MODEL: raw BODYBRIDGE_TOKEN as bearer is now rejected",
      (not called) and status == 401, f"downstream called={called}, status={status}")

resp = run(server.oauth_authorize(make_get("/oauth/authorize", {
    **authorize_params, "client_id": "totally-forged-client-id",
})))
check("forged client_id -> hard rejected (no redirect)",
      "location" not in {k.lower() for k in resp.headers.keys()} and resp.status_code == 400,
      f"status={resp.status_code}")

print(f"\n=== {len(FAILURES) == 0 and 'ALL CHECKS PASSED' or f'{len(FAILURES)} FAILURE(S)'} ===")
for f in FAILURES:
    print(f"  FAILED: {f}")
sys.exit(1 if FAILURES else 0)
