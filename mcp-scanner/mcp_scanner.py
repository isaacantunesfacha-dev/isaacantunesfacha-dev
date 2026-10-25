#!/usr/bin/env python3
"""Static, offline checks for common MCP client configuration risks."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


SENSITIVE_NAME = ("token", "secret", "password", "api_key", "apikey", "credential", "auth")
AUTH_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
ENV_REFERENCE = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$")
RECOMMENDATIONS = {
    "package_runner": "Fixe versões e origem do pacote; prefira instalação reproduzível e revisão de dependências.",
    "cleartext_transport": "Use HTTPS para proteger dados e credenciais durante o transporte.",
    "inline_auth_header": "Injete o valor por variável de ambiente ou gerenciador de segredos.",
    "inline_sensitive_env": "Remova o segredo do arquivo e injete-o pelo ambiente em tempo de execução.",
    "relative_command": "Use caminho absoluto confiável ou resolva o executável em ambiente controlado.",
}


def _validate_server(name: Any, server: Any) -> None:
    """Validate supported MCP server config shapes without echoing values."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Nomes de servidor MCP precisam ser textos não vazios.")
    if not isinstance(server, dict):
        raise ValueError(f"A configuração do servidor '{name}' precisa ser um objeto.")

    command, url = server.get("command"), server.get("url")
    transport = server.get("type", "stdio" if command is not None else "http")
    if not isinstance(transport, str) or transport not in {"stdio", "http", "sse"}:
        raise ValueError(f"Transporte não suportado no servidor '{name}'.")
    if transport == "stdio":
        if not isinstance(command, str) or not command.strip() or url is not None:
            raise ValueError(f"Servidor stdio '{name}' precisa de command e não pode definir url.")
    else:
        if not isinstance(url, str) or command is not None:
            raise ValueError(f"Servidor remoto '{name}' precisa de url e não pode definir command.")
        try:
            parsed = urlsplit(url)
        except ValueError as exc:
            raise ValueError(f"URL inválida no servidor '{name}'.") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(f"URL inválida no servidor '{name}'; credenciais devem ficar em headers.")

    for key, expected in (("args", list), ("env", dict), ("headers", dict)):
        value = server.get(key, expected())
        if not isinstance(value, expected):
            raise ValueError(f"'{key}' inválido no servidor '{name}'.")
    if any(not isinstance(arg, str) for arg in server.get("args", [])):
        raise ValueError(f"'args' do servidor '{name}' precisa conter apenas textos.")
    for key in ("env", "headers"):
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in server.get(key, {}).items()):
            raise ValueError(f"'{key}' do servidor '{name}' precisa mapear textos para textos.")
    if transport == "stdio" and server.get("headers"):
        raise ValueError(f"'headers' só é aceito em servidores remotos ('{name}').")


def scan_config(config: Any) -> list[dict[str, str]]:
    """Return findings without including configured values or secrets."""
    if not isinstance(config, dict):
        raise ValueError("A raiz da configuração precisa ser um objeto JSON.")

    servers = config.get("mcpServers", config.get("servers", {}))
    if not isinstance(servers, dict):
        raise ValueError("'mcpServers' ou 'servers' precisa ser um objeto JSON.")

    findings: list[dict[str, str]] = []
    for name, server in servers.items():
        _validate_server(name, server)

        command = server.get("command")
        url = server.get("url", "")

        def add(rule: str, severity: str, message: str) -> None:
            findings.append({
                "server": str(name), "rule": rule, "severity": severity,
                "message": message, "recommendation": RECOMMENDATIONS[rule],
            })

        if isinstance(command, str) and Path(command).name in {"npx", "uvx"}:
            add("package_runner", "medium", "Servidor usa um runner que pode baixar código ao iniciar.")
        if isinstance(url, str) and urlsplit(url).scheme == "http":
            add("cleartext_transport", "high", "URL HTTP não protege o tráfego com TLS.")
        headers = server.get("headers", {})
        if isinstance(headers, dict):
            for key, value in headers.items():
                if key.lower() in AUTH_HEADERS and not ENV_REFERENCE.fullmatch(value):
                    add("inline_auth_header", "high", f"Cabeçalho '{key}' contém valor inline; use uma referência a variável de ambiente.")

        env = server.get("env", {})
        if isinstance(env, dict):
            for key in env:
                if any(part in key.lower() for part in SENSITIVE_NAME) and not ENV_REFERENCE.fullmatch(env[key]):
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
