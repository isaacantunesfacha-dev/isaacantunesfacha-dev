#!/usr/bin/env python3
"""Static, offline checks for common MCP client configuration risks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SENSITIVE_NAME = ("token", "secret", "password", "api_key", "apikey", "credential", "auth")


def scan_config(config: Any) -> list[dict[str, str]]:
    """Return findings without including configured values or secrets."""
    if not isinstance(config, dict):
        raise ValueError("A raiz da configuração precisa ser um objeto JSON.")

    servers = config.get("mcpServers", config.get("servers", {}))
    if not isinstance(servers, dict):
        raise ValueError("'mcpServers' ou 'servers' precisa ser um objeto JSON.")

    findings: list[dict[str, str]] = []
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue

        command = server.get("command")
        url = server.get("url", "")

        def add(rule: str, severity: str, message: str) -> None:
            findings.append({"server": str(name), "rule": rule, "severity": severity, "message": message})

        if isinstance(command, str) and Path(command).name in {"npx", "uvx"}:
            add("package_runner", "medium", "Servidor usa um runner que pode baixar código ao iniciar.")
        if isinstance(url, str) and url.lower().startswith("http://"):
            add("cleartext_transport", "high", "URL HTTP não protege o tráfego com TLS.")
        headers = server.get("headers", {})
        if isinstance(headers, dict):
            for key in headers:
                add("inline_auth_header", "high", f"Cabeçalho '{key}' está declarado inline; use uma referência a variável de ambiente.")

        env = server.get("env", {})
        if isinstance(env, dict):
            for key in env:
                if any(part in str(key).lower() for part in SENSITIVE_NAME):
                    add("inline_sensitive_env", "medium", f"'{key}' pode conter credencial; mantenha o valor fora do arquivo compartilhado.")

        if isinstance(command, str) and command and not Path(command).is_absolute() and Path(command).parent != Path("."):
            add("relative_command", "low", "Comando relativo depende do PATH e do diretório de execução.")

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="arquivo JSON de configuração MCP")
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        findings = scan_config(config)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2

    print(json.dumps({"findings": findings, "count": len(findings)}, ensure_ascii=False, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
