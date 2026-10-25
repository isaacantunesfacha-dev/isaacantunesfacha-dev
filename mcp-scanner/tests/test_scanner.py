import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcp_scanner import scan_config


class ScanConfigTests(unittest.TestCase):
    def test_reports_risky_patterns_without_leaking_values(self):
        findings = scan_config({"mcpServers": {"demo": {
            "command": "npx", "args": ["secret-package"],
            "url": "http://example.test/mcp",
            "headers": {"Authorization": "Bearer do-not-print"},
            "env": {"API_TOKEN": "do-not-print"},
        }}})
        rules = {item["rule"] for item in findings}
        self.assertEqual(rules, {"package_runner", "cleartext_transport", "inline_auth_header", "inline_sensitive_env"})
        self.assertNotIn("do-not-print", str(findings))
        self.assertNotIn("secret-package", str(findings))

    def test_clean_absolute_command_has_no_findings(self):
        self.assertEqual(scan_config({"mcpServers": {"local": {"command": "/usr/bin/python3"}}}), [])

    def test_rejects_invalid_root_or_server_collection(self):
        for config in ([], {"mcpServers": []}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                scan_config(config)


if __name__ == "__main__":
    unittest.main()
