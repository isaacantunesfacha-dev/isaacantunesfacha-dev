import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcp_scanner import scan_config


class ScanConfigTests(unittest.TestCase):
    def test_reports_risky_patterns_without_leaking_values(self):
        findings = scan_config({"mcpServers": {
            "local": {"command": "npx", "args": ["secret-package"], "env": {"API_TOKEN": "do-not-print"}},
            "remote": {"type": "http", "url": "http://example.test/mcp",
                       "headers": {"Authorization": "Bearer do-not-print"}},
        }})
        rules = {item["rule"] for item in findings}
        self.assertEqual(rules, {"package_runner", "cleartext_transport", "inline_auth_header", "inline_sensitive_env"})
        self.assertNotIn("do-not-print", str(findings))
        self.assertNotIn("secret-package", str(findings))

    def test_clean_absolute_command_has_no_findings(self):
        self.assertEqual(scan_config({"mcpServers": {"local": {"command": "/usr/bin/python3"}}}), [])

    def test_remote_references_and_non_auth_headers_are_not_flagged(self):
        config = {"mcpServers": {"remote": {
            "type": "http", "url": "https://mcp.example.test/rpc",
            "headers": {"Authorization": "${MCP_TOKEN}", "Accept": "application/json"},
            "env": {"API_TOKEN": "${API_TOKEN}"},
        }}}
        self.assertEqual(scan_config(config), [])

    def test_rejects_malformed_server_without_echoing_config_values(self):
        secret = "Bearer-private-value"
        with self.assertRaises(ValueError) as error:
            scan_config({"mcpServers": {"demo": {"command": [secret]}}})
        self.assertNotIn(secret, str(error.exception))

    def test_reports_inline_auth_only_for_remote_auth_headers(self):
        findings = scan_config({"mcpServers": {"remote": {
            "type": "sse", "url": "http://localhost:9000/events",
            "headers": {"Authorization": "Bearer private"},
        }}})
        self.assertEqual({item["rule"] for item in findings}, {"cleartext_transport", "inline_auth_header"})
        self.assertNotIn("private", str(findings))

    def test_rejects_invalid_root_or_server_collection(self):
        for config in ([], {"mcpServers": []}, {"mcpServers": {"bad": None}},
                       {"mcpServers": {"bad": {"type": []}}},
                       {"mcpServers": {"bad": {"command": "python", "args": "not-a-list"}}}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                scan_config(config)


if __name__ == "__main__":
    unittest.main()
