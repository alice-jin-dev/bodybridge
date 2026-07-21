"""Regression checks for the device-contract layer (DeviceResult / _safe /
resource normalization). Complements scripts/oauth_flow_check.py, which
covers the OAuth chain instead.

Run it any time after touching server.py's _safe or the DeviceResult contract:

    python scripts/contract_check.py

Drives the REAL server.py functions directly (no network socket, no port
bound). Exit code is 0 if every check passes, 1 otherwise.
"""
import asyncio
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")

# Fresh throwaway secrets for this run only -- server.py refuses to import-run
# without them at __main__, but importing as a module here just needs them set
# so nothing downstream complains. Never reused, never written anywhere.
os.environ["BODYBRIDGE_TOKEN"] = "contract-check-" + os.urandom(16).hex()
os.environ["BODYBRIDGE_PASSWORD"] = "contract-check-" + os.urandom(16).hex()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402
from adapters.base import ErrorCode  # noqa: E402

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def run(coro):
    return asyncio.run(coro)


# --- _safe deadline: a coro that sleeps past the deadline must come back as
# TIMEOUT, never internal_error ---------------------------------------------
# This guards the one thing only a code comment currently protects: the
# `except asyncio.TimeoutError` clause MUST sit before `except Exception` in
# _safe. asyncio.TimeoutError is itself an Exception subclass, so if a future
# refactor reorders them, the timeout gets silently swallowed as
# internal_error -- no crash, no red test elsewhere, the TIMEOUT code just
# never appears. This check would go red the moment that happens.

async def _sleeps_past_deadline():
    await asyncio.sleep(60)   # far beyond the tiny deadline we set below
    from adapters.base import DeviceResult
    return DeviceResult.success("should never get here")


async def _timeout_case():
    # Squeeze the deadline down so the test is instant instead of waiting 25s.
    original = server.COMMAND_TIMEOUT_SECONDS
    server.COMMAND_TIMEOUT_SECONDS = 0.05
    try:
        return await server._safe(_sleeps_past_deadline())
    finally:
        server.COMMAND_TIMEOUT_SECONDS = original


result = run(_timeout_case())

check("timeout -> error is TIMEOUT, not internal_error "
      "(except-order regression guard)",
      result["error"] == ErrorCode.TIMEOUT,
      f"got error={result['error']!r}")
check("timeout -> retryable is False (to/from device is unknown, not a "
      "confirmed non-delivery)",
      result["retryable"] is False,
      f"got retryable={result['retryable']!r}")
check("timeout -> ok is False", result["ok"] is False,
      f"got ok={result['ok']!r}")
check("timeout -> message does not claim the command 'failed' "
      "(must express uncertainty, not lie)",
      "失败" not in result["message"],
      f"message={result['message']!r}")

# Language-agnostic guard beside the one above. The "失败" check hardcodes the
# current Chinese wording; once the release checklist's "user-facing errors ->
# English" item lands, that check turns into an always-true no-op that silently
# stops testing anything (same trap as the except-order comment). This keyword
# table covers "asserting the command definitely failed" in BOTH languages, so
# it keeps biting after the wording changes.
# ⚠️ WHEN THE MESSAGE LANGUAGE CHANGES, UPDATE THIS KEYWORD TABLE to match the
# new wording -- otherwise this guard rots into the same silent no-op.
_FAILURE_CLAIM_KEYWORDS = ("失败", "failed", "failure")
_msg_lower = result["message"].lower()
_hit = [kw for kw in _FAILURE_CLAIM_KEYWORDS if kw.lower() in _msg_lower]
check("timeout -> message contains no definite-failure wording in any covered "
      "language (keyword table must be kept in sync with the message wording)",
      not _hit,
      f"forbidden wording present: {_hit}; message={result['message']!r}")


# --- resource URL normalization: harmless differences (case / trailing slash
# / default :443 / fragment) must compare EQUAL after normalization; a real
# mismatch must still compare unequal (so it's still rejected as invalid_target).
# Guards the "normalize both sides before comparing" axis -- NOT the
# "== vs constant-time compare" axis, which is intentionally left as plain ==.

_CANON = "https://bridge.example.com/mcp"
_canon_norm = server._normalize_resource_url(_CANON)

# each of these differs from _CANON only in a normalization-invariant way:
_EQUIVALENT = [
    ("case (scheme + host uppercased)", "HTTPS://Bridge.Example.COM/mcp"),
    ("trailing slash", "https://bridge.example.com/mcp/"),
    ("explicit default port :443", "https://bridge.example.com:443/mcp"),
    ("fragment", "https://bridge.example.com/mcp#section"),
]
for _label, _variant in _EQUIVALENT:
    check(f"resource normalize -> equal despite {_label}",
          server._normalize_resource_url(_variant) == _canon_norm,
          f"{_variant!r} normalized to "
          f"{server._normalize_resource_url(_variant)!r}, expected {_canon_norm!r}")

# real mismatches must STILL differ after normalization (still get rejected):
_MISMATCH = [
    ("different host", "https://evil.example.com/mcp"),
    ("different path", "https://bridge.example.com/other"),
    # path case is deliberately NOT normalized, so /MCP is a genuine mismatch:
    ("path case differs (path case is not normalized)",
     "https://bridge.example.com/MCP"),
]
for _label, _variant in _MISMATCH:
    check(f"resource normalize -> still unequal for {_label} (must stay rejected)",
          server._normalize_resource_url(_variant) != _canon_norm,
          f"{_variant!r} normalized to "
          f"{server._normalize_resource_url(_variant)!r}, which wrongly matched "
          f"{_canon_norm!r}")


print(f"\n=== {len(FAILURES) == 0 and 'ALL CHECKS PASSED' or f'{len(FAILURES)} FAILURE(S)'} ===")
for f in FAILURES:
    print(f"  FAILED: {f}")
sys.exit(1 if FAILURES else 0)
