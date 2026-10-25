import unittest
import sys
import json
import subprocess
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcp_scanner import scan_config


class ScanConfigTests(unittest.TestCase):
    def test_synthetic_fixture_corpus_and_recommendations(self):
        fixtures = Path(__file__).parent / "fixtures"
        clean = json.loads((fixtures / "clean.json").read_text(encoding="utf-8"))
        risky = json.loads((fixtures / "risky.json").read_text(encoding="utf-8"))
        self.assertEqual(scan_config(clean), [])
        findings = scan_config(risky)
        self.assertEqual({finding["rule"] for finding in findings}, {
            "package_runner", "inline_sensitive_env", "cleartext_transport", "inline_auth_header",
        })
        self.assertTrue(all(finding["recommendation"] for finding in findings))

    def test_cli_fail_threshold_formats_sarif_and_keeps_labels_private(self):
        project = Path(__file__).resolve().parents[1]
        scanner = project / "mcp_scanner.py"
        config = Path(__file__).parent / "fixtures" / "risky.json"
        sarif = subprocess.run(
            [sys.executable, str(scanner), "scan", str(config), "--format", "sarif", "--fail-on", "high"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(sarif.returncode, 1)
        report = json.loads(sarif.stdout)
        self.assertEqual(report["version"], "2.1.0")
        self.assertTrue(all(result["locations"] for result in report["runs"][0]["results"]))
        self.assertNotIn("local-risky", sarif.stdout)
        self.assertNotIn("synthetic-placeholder", sarif.stdout)
        self.assertNotIn("API_TOKEN", sarif.stdout)

        high_threshold = subprocess.run(
            [sys.executable, str(scanner), "scan", str(config), "--fail-on", "high", "--format", "json"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(high_threshold.returncode, 1)

        with tempfile.TemporaryDirectory() as temp_dir:
            low_config = Path(temp_dir) / "low.json"
            output = Path(temp_dir) / "report.json"
            low_config.write_text(json.dumps({"mcpServers": {"private-server-name": {"command": "npx"}}}), encoding="utf-8")
            below_threshold = subprocess.run(
                [sys.executable, str(scanner), "scan", str(low_config), "--fail-on", "high", "--output", str(output)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(below_threshold.returncode, 0)
            report_text = output.read_text(encoding="utf-8")
            self.assertNotIn("private-server-name", report_text)
            self.assertNotIn("\"API_TOKEN\"", report_text)

        ignored = subprocess.run(
            [sys.executable, str(scanner), "scan", str(config), "--fail-on", "none", "--format", "text"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(ignored.returncode, 0)
        self.assertNotIn("synthetic-placeholder", ignored.stdout)


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
