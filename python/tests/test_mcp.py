"""Tests for the MCP gating proxy (mandatekit.mcp).

The gate must be fail-closed: anything that is not a verifiably in-scope
tools/call gets denied or dropped, never forwarded.
"""

import json
import unittest

from mandatekit import build_mandate, generate_keypair, sign_mandate
from mandatekit.mcp import DROP, FORWARD, RESPOND, gate_line


def make_signed(categories=None, merchants=None, max_amount=None):
    private_key, public_key = generate_keypair()
    mandate = build_mandate(
        agent_id="agent-under-test",
        categories=categories,
        merchants=merchants,
        max_amount=max_amount,
        ttl_days=1,
    )
    signed = sign_mandate(mandate, private_key)
    trusted = [signed["signature"]["public_key"]]
    return signed, trusted, public_key


def call(name, arguments=None, msg_id=7):
    msg = {"jsonrpc": "2.0", "id": msg_id,
           "method": "tools/call",
           "params": {"name": name, "arguments": arguments or {}}}
    return json.dumps(msg)


class TestGateLine(unittest.TestCase):
    def test_allowed_tool_forwards(self):
        signed, trusted, _ = make_signed(categories=["search_web", "read_file"])
        action, payload = gate_line(call("search_web"), signed, trusted)
        self.assertEqual(action, FORWARD)
        self.assertIsNone(payload)

    def test_disallowed_tool_denied_with_response(self):
        signed, trusted, _ = make_signed(categories=["search_web"])
        action, payload = gate_line(call("delete_repo"), signed, trusted)
        self.assertEqual(action, RESPOND)
        self.assertEqual(payload["id"], 7)
        self.assertTrue(payload["result"]["isError"])
        self.assertIn("denied", payload["result"]["content"][0]["text"])

    def test_non_tools_call_passes_through(self):
        signed, trusted, _ = make_signed(categories=["search_web"])
        for method in ("initialize", "tools/list", "resources/list", "ping"):
            msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method})
            action, _ = gate_line(msg, signed, trusted)
            self.assertEqual(action, FORWARD, method)

    def test_unparseable_line_dropped(self):
        signed, trusted, _ = make_signed(categories=["search_web"])
        action, _ = gate_line("this is not json", signed, trusted)
        self.assertEqual(action, DROP)
        action, _ = gate_line('"a bare json string"', signed, trusted)
        self.assertEqual(action, DROP)

    def test_untrusted_signer_denied(self):
        signed, _, _ = make_signed(categories=["search_web"])
        _, other_public = generate_keypair()
        import base64
        stranger = base64.b64encode(other_public).decode()
        action, payload = gate_line(call("search_web"), signed, [stranger])
        self.assertEqual(action, RESPOND)
        self.assertTrue(payload["result"]["isError"])

    def test_amount_over_cap_denied(self):
        signed, trusted, _ = make_signed(
            categories=["pay_invoice"],
            max_amount={"value": 500, "currency": "USD"},
        )
        over = call("pay_invoice", {"amount": {"value": 900, "currency": "USD"}})
        action, payload = gate_line(over, signed, trusted)
        self.assertEqual(action, RESPOND)
        under = call("pay_invoice", {"amount": {"value": 400, "currency": "USD"}})
        action, _ = gate_line(under, signed, trusted)
        self.assertEqual(action, FORWARD)

    def test_amount_required_when_capped(self):
        # A mandate with a spend cap denies a capped tool call with no amount:
        # the verifier treats a missing amount as failing the amount check.
        signed, trusted, _ = make_signed(
            categories=["pay_invoice"],
            max_amount={"value": 500, "currency": "USD"},
        )
        action, _ = gate_line(call("pay_invoice"), signed, trusted)
        self.assertEqual(action, RESPOND)

    def test_server_name_pins_merchant(self):
        signed, trusted, _ = make_signed(
            categories=["search_web"],
            merchants={"allow": ["prod-search-server"]},
        )
        action, _ = gate_line(call("search_web"), signed, trusted,
                              server_name="prod-search-server")
        self.assertEqual(action, FORWARD)
        action, _ = gate_line(call("search_web"), signed, trusted,
                              server_name="rogue-server")
        self.assertEqual(action, RESPOND)

    def test_denied_notification_dropped_not_answered(self):
        signed, trusted, _ = make_signed(categories=["search_web"])
        msg = json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                          "params": {"name": "delete_repo", "arguments": {}}})
        action, payload = gate_line(msg, signed, trusted)
        self.assertEqual(action, DROP)
        self.assertIsNone(payload)

    def test_tampered_mandate_denied(self):
        signed, trusted, _ = make_signed(categories=["search_web"])
        signed["mandate"]["constraints"]["categories"].append("delete_repo")
        action, payload = gate_line(call("delete_repo"), signed, trusted)
        self.assertEqual(action, RESPOND)
        self.assertIn("signature", payload["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
