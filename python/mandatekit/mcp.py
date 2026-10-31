"""MCP gating proxy: enforce a signed mandate on every MCP tool call.

Sits between an MCP client (an agent) and an MCP server over the stdio
transport, which frames messages as newline-delimited JSON-RPC 2.0. Every
``tools/call`` request is checked against a signed mandate before it reaches
the server; everything else passes through untouched.

    mandatekit-mcp --mandate signed.json --trust @issuer.pub -- python -m some_mcp_server

Mapping from a tool call onto the mandate's constraint vocabulary:

- the tool name is the transaction ``category`` (so ``categories`` in the
  mandate is a signed tool allowlist),
- ``--server-name`` (optional) becomes the transaction ``merchant`` (so
  merchant allow/deny lists can pin which server a mandate is for),
- a top-level ``amount`` object in the tool arguments, shaped
  ``{"value": <int>, "currency": "<str>"}``, is passed through so
  ``max_amount`` caps per-call spend for payment-shaped tools.

Fail-closed, in keeping with the rest of the kit:

- a ``tools/call`` that cannot be parsed, mapped, or verified is denied,
  never forwarded;
- a denial is returned to the client as a normal MCP tool result with
  ``isError: true``, so the agent sees *why* and the session survives;
- issuer trust is mandatory: the proxy will not start without ``--trust``.

0.2: the proxy keeps an in-memory usage store for the session and records
every forwarded call, so a mandate's ``limits`` (for example ``max_uses``)
hold across the session; ``--revocation-list @file`` (repeatable) supplies the
signed lists a mandate declares under ``revocation``. The store does not
survive the proxy process; a mandate with ``limits`` starts each session at
zero uses.

Stdlib only. No model, no network. A deny is a deny before the server ever
sees the request.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .store import InMemoryUsageStore
from .verifier import record_use, verify

# Gate outcomes for a single client->server line.
FORWARD = "forward"   # pass the original line to the server
RESPOND = "respond"   # do not forward; send this JSON-RPC response to the client
DROP = "drop"         # do not forward; nothing to say (unparseable, or denied notification)

# A JSON-RPC frame longer than this is dropped unparsed. MCP tool calls are small; a frame
# this size is either a bug or an attempt to exhaust the proxy.
MAX_LINE_CHARS = 1 << 20  # 1 MiB


def _log(message: str) -> None:
    print(f"mandatekit-mcp: {message}", file=sys.stderr)


def load_trusted(arg: str) -> str:
    """Resolve --trust: a base64 public key, or @path to a file containing one."""
    if arg.startswith("@"):
        with open(arg[1:], "r", encoding="utf-8") as f:
            return f.read().strip()
    return arg.strip()


def _amount_from_args(arguments: Dict) -> Optional[Dict]:
    amount = arguments.get("amount")
    if not isinstance(amount, dict):
        return None
    value, currency = amount.get("value"), amount.get("currency")
    if isinstance(value, int) and not isinstance(value, bool) and isinstance(currency, str):
        return {"value": value, "currency": currency}
    return None


def _deny_response(request_id, rationale: str) -> Dict:
    """An MCP tool result carrying the denial, so the agent sees the reason."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": f"mandatekit denied this call: {rationale}"}],
            "isError": True,
        },
    }


def load_json_arg(arg: str):
    """Resolve a JSON argument: inline JSON, or @path to a file containing it."""
    if arg.startswith("@"):
        with open(arg[1:], "r", encoding="utf-8") as f:
            return json.load(f)
    return json.loads(arg)


def gate_line(
    line: str,
    signed: Dict,
    trusted: List[str],
    server_name: Optional[str] = None,
    store=None,
    revocation_lists=None,
    now: Optional[datetime] = None,
) -> Tuple[str, Optional[Dict]]:
    """Decide what to do with one client->server line. Fail-closed throughout.

    `store` holds usage state for a mandate with `limits`; a forwarded call is
    recorded in it. `revocation_lists` carries the signed lists a mandate
    declares. `now` pins the clock (tests); the wall clock otherwise."""
    if len(line) > MAX_LINE_CHARS:
        _log(f"dropped a {len(line)}-character frame (limit {MAX_LINE_CHARS}); fail-closed")
        return DROP, None
    try:
        msg = json.loads(line)
    except (ValueError, TypeError, RecursionError, MemoryError) as e:
        # Deep nesting raises RecursionError inside json; a pathological frame can raise
        # MemoryError. Neither may take the proxy down: the frame is dropped, nothing forwards.
        _log(f"dropped an unparseable frame ({e.__class__.__name__}); fail-closed")
        return DROP, None
    if not isinstance(msg, dict):
        return DROP, None
    if msg.get("method") != "tools/call":
        return FORWARD, None

    request_id = msg.get("id")
    try:
        params = msg.get("params")
        params = params if isinstance(params, dict) else {}
        name = params.get("name")
        arguments = params.get("arguments")
        arguments = arguments if isinstance(arguments, dict) else {}
        if not isinstance(name, str) or not name:
            raise ValueError("tools/call without a tool name")

        transaction: Dict = {
            "category": name,
            "description": f"MCP tool call: {name}",
        }
        if server_name:
            transaction["merchant"] = server_name
        amount = _amount_from_args(arguments)
        if amount is not None:
            transaction["amount"] = amount

        verdict = verify(signed, transaction, trusted_keys=trusted, now=now,
                         store=store, revocation_lists=revocation_lists)
        if verdict.get("decision") == "allow":
            if store is not None:
                record_use(signed, transaction, store, now=now)
            return FORWARD, None
        rationale = verdict.get("rationale") or "denied by mandate"
    except Exception as e:  # any gating failure is a deny, never a forward
        rationale = f"gating error ({e.__class__.__name__}); denied fail-closed"

    if request_id is None:
        return DROP, None
    return RESPOND, _deny_response(request_id, rationale)


def _pump(src, dst) -> None:
    """Copy src to dst line-by-line until EOF."""
    try:
        for chunk in src:
            dst.write(chunk)
            dst.flush()
    except (BrokenPipeError, ValueError, OSError):
        pass


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mandatekit-mcp",
        description="Gate an MCP server's tool calls behind a signed mandate.",
    )
    parser.add_argument("--mandate", required=True,
                        help="path to a signed mandate JSON file")
    parser.add_argument("--trust", required=True,
                        help="trusted issuer public key (base64), or @path to a key file")
    parser.add_argument("--server-name", default=None,
                        help="optional merchant name for this server, matched against the "
                             "mandate's merchant allow/deny lists")
    parser.add_argument("--revocation-list", action="append", default=[], metavar="JSON_OR_@FILE",
                        help="a signed revocation list the mandate declares (inline JSON or @path). Repeatable.")
    parser.add_argument("server", nargs=argparse.REMAINDER,
                        help="-- followed by the MCP server command to wrap")
    args = parser.parse_args(argv)

    server_cmd = args.server
    if server_cmd and server_cmd[0] == "--":
        server_cmd = server_cmd[1:]
    if not server_cmd:
        parser.error("no server command given; usage: mandatekit-mcp [options] -- <server cmd>")

    with open(args.mandate, "r", encoding="utf-8") as f:
        signed = json.load(f)
    trusted = [load_trusted(args.trust)]
    revocation_lists = [load_json_arg(a) for a in args.revocation_list]
    store = InMemoryUsageStore()

    child = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )

    out_pump = threading.Thread(target=_pump, args=(child.stdout, sys.stdout), daemon=True)
    out_pump.start()

    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            action, payload = gate_line(line, signed, trusted, args.server_name,
                                        store=store, revocation_lists=revocation_lists)
            if action == FORWARD:
                child.stdin.write(line)
                child.stdin.flush()
            elif action == RESPOND:
                sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
                sys.stdout.flush()
                print(f"mandatekit-mcp: denied tools/call id={payload['id']}", file=sys.stderr)
            else:
                print("mandatekit-mcp: dropped unparseable or denied frame", file=sys.stderr)
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        try:
            child.stdin.close()
        except OSError:
            pass
        child.wait()

    return child.returncode or 0


if __name__ == "__main__":
    sys.exit(main())
