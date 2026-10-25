#!/usr/bin/env python3
"""Static, offline checks for common MCP client configuration risks."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit


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
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}
SECURITY_SCORE = {"low": "2.5", "medium": "5.0", "high": "7.5", "critical": "9.5"}
EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", "vendor", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".cache", ".next", ".terraform", "coverage", "build", "dist", "target"}
MAX_CONFIG_FILES = 500
MAX_CONFIG_BYTES = 1_048_576


def _validate_server(name: Any, server: Any) -> None:
    """Validate supported MCP server config shapes without echoing values."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Nome de servidor MCP inválido.")
    if not isinstance(server, dict):
        raise ValueError("Configuração de servidor MCP precisa ser um objeto.")

    command, url = server.get("command"), server.get("url")
    transport = server.get("type", "stdio" if command is not None else "http")
    if not isinstance(transport, str) or transport not in {"stdio", "http", "sse"}:
        raise ValueError("Transporte MCP não suportado.")
    if transport == "stdio":
        if not isinstance(command, str) or not command.strip() or url is not None:
            raise ValueError("Servidor stdio precisa de command e não pode definir url.")
    else:
        if not isinstance(url, str) or command is not None:
            raise ValueError("Servidor remoto precisa de url e não pode definir command.")
        try:
            parsed = urlsplit(url)
            _ = parsed.port  # Validate port syntax without echoing the URL.
        except ValueError as exc:
            raise ValueError("URL MCP inválida.") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("URL MCP inválida; credenciais devem ficar em headers.")

    for key, expected in (("args", list), ("env", dict), ("headers", dict)):
        value = server.get(key, expected())
        if not isinstance(value, expected):
            raise ValueError(f"Campo MCP '{key}' inválido.")
    if any(not isinstance(arg, str) for arg in server.get("args", [])):
        raise ValueError("Campo MCP 'args' precisa conter apenas textos.")
    for key in ("env", "headers"):
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in server.get(key, {}).items()):
            raise ValueError(f"Campo MCP '{key}' precisa mapear textos para textos.")
    if transport == "stdio" and server.get("headers"):
        raise ValueError("Campo MCP 'headers' só é aceito em servidores remotos.")


def scan_config(config: Any) -> list[dict[str, str]]:
    """Return findings without including configured values or secrets."""
    if not isinstance(config, dict):
        raise ValueError("A raiz da configuração precisa ser um objeto JSON.")

    servers = config.get("mcpServers", config.get("servers", {}))
    if not isinstance(servers, dict):
        raise ValueError("'mcpServers' ou 'servers' precisa ser um objeto JSON.")

    findings: list[dict[str, str]] = []
    for index, (name, server) in enumerate(servers.items(), start=1):
        _validate_server(name, server)

        command = server.get("command")
        url = server.get("url", "")

        def add(rule: str, severity: str, message: str) -> None:
            findings.append({
                "server": f"server-{index}", "rule": rule, "severity": severity,
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
                    add("inline_auth_header", "high", "Cabeçalho de autenticação contém valor inline; use uma referência a variável de ambiente.")

        env = server.get("env", {})
        if isinstance(env, dict):
            for key in env:
                if any(part in key.lower() for part in SENSITIVE_NAME) and not ENV_REFERENCE.fullmatch(env[key]):
                    add("inline_sensitive_env", "medium", "Variável de ambiente sensível contém valor inline; injete o segredo em tempo de execução.")

        if isinstance(command, str) and command and not Path(command).is_absolute() and Path(command).parent != Path("."):
            add("relative_command", "low", "Comando relativo depende do PATH e do diretório de execução.")

    return findings


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.name


def discover_configs(inputs: list[Path]) -> tuple[list[Path], list[str]]:
    """Collect JSON files from explicit files/directories without following symlinks."""
    files: list[Path] = []
    errors: list[str] = []
    seen: set[Path] = set()

    def add(path: Path) -> bool:
        resolved = path.resolve()
        if resolved in seen:
            return True
        if len(files) >= MAX_CONFIG_FILES:
            errors.append(f"Limite de arquivos atingido ({MAX_CONFIG_FILES}).")
            return False
        seen.add(resolved)
        files.append(path)
        return True

    for item in inputs:
        if item.is_symlink():
            errors.append(f"{_display_path(item)}: link simbólico ignorado.")
        elif item.is_file():
            if not add(item):
                return files, errors
        elif item.is_dir():
            def walk_error(error: OSError) -> None:
                errors.append(f"{_display_path(Path(error.filename or item))}: diretório não pôde ser lido.")

            for root, dirs, names in os.walk(item, topdown=True, followlinks=False, onerror=walk_error):
                base = Path(root)
                relative_parts = base.relative_to(item).parts
                dirs[:] = [
                    name for name in dirs
                    if name not in EXCLUDED_DIRS
                    and not (len(relative_parts) >= 1 and relative_parts[-1] in {"test", "tests"} and name == "fixtures")
                    and not (base / name).is_symlink()
                ]
                for name in sorted(names):
                    candidate = base / name
                    if name.lower().endswith(".json") and not candidate.is_symlink():
                        if not add(candidate):
                            return files, errors
        else:
            errors.append(f"{_display_path(item)}: caminho inexistente ou tipo não suportado.")
    return files, errors


def sarif_report(findings: list[dict[str, str]], source: Path | None = None) -> dict[str, Any]:
    """Build SARIF 2.1.0 with repository-relative config URIs."""
    rules = sorted({finding["rule"] for finding in findings})
    rule_indexes = {rule: index for index, rule in enumerate(rules)}
    descriptors = [{
        "id": rule,
        "name": rule,
        "shortDescription": {"text": rule.replace("_", " ").capitalize()},
        "defaultConfiguration": {"level": SARIF_LEVEL[next(f["severity"] for f in findings if f["rule"] == rule)]},
        "properties": {
            "tags": ["security"],
            "precision": "medium",
            "security-severity": SECURITY_SCORE[next(f["severity"] for f in findings if f["rule"] == rule)],
        },
    } for rule in rules]
    results = []
    for finding in findings:
        uri = _sarif_uri(Path(finding.get("source", str(source or ""))))
        results.append({
            "ruleId": finding["rule"],
            "ruleIndex": rule_indexes[finding["rule"]],
            "level": SARIF_LEVEL[finding["severity"]],
            "message": {"text": f"{finding['message']} Recomendação: {finding['recommendation']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpScanner/v1": f"{uri}:{finding['server']}:{finding['rule']}"
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "MCP Scanner", "semanticVersion": "0.1.0", "rules": descriptors}}, "results": results}],
    }


def _sarif_uri(source: Path) -> str:
    try:
        return quote(source.resolve().relative_to(Path.cwd().resolve()).as_posix(), safe="/")
    except ValueError:
        return quote(source.name, safe="")


def _render_text(findings: list[dict[str, str]]) -> str:
    if not findings:
        return "Nenhum risco encontrado."
    return "\n".join(
        f"[{item['severity'].upper()}] {item.get('source', 'config')} / {item['server']} / {item['rule']}: {item['message']}\n  Recomendação: {item['recommendation']}"
        for item in findings
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="analisar uma configuração MCP JSON")
    scan.add_argument("configs", type=Path, nargs="+", help="arquivos JSON e/ou diretórios para busca")
    scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="low",
                      help="severidade mínima que faz o comando retornar código 1 (padrão: low)")
    scan.add_argument("--format", choices=["json", "text", "sarif"], default="json", help="formato do relatório")
    scan.add_argument("-o", "--output", type=Path, help="arquivo de saída; padrão: stdout")
    args = parser.parse_args(argv)
    paths, errors = discover_configs(args.configs)
    if not paths:
        errors.append("Nenhum arquivo JSON de configuração foi encontrado.")
    findings: list[dict[str, str]] = []
    files_scanned = 0
    for path in paths:
        try:
            with path.open("rb") as config_file:
                raw_config = config_file.read(MAX_CONFIG_BYTES + 1)
            if len(raw_config) > MAX_CONFIG_BYTES:
                errors.append(f"{_display_path(path)}: arquivo excede o limite de {MAX_CONFIG_BYTES} bytes.")
                continue
            config = json.loads(raw_config.decode("utf-8"))
            file_findings = scan_config(config)
        except OSError:
            errors.append(f"{_display_path(path)}: arquivo não pôde ser lido.")
            continue
        except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
            errors.append(f"{_display_path(path)}: JSON ou configuração MCP inválida.")
            continue
        files_scanned += 1
        findings.extend({**finding, "source": _display_path(path)} for finding in file_findings)

    if args.format == "json":
        output = json.dumps({"files_scanned": files_scanned, "findings": findings, "count": len(findings), "errors": errors}, ensure_ascii=False, indent=2)
    elif args.format == "sarif":
        output = json.dumps(sarif_report(findings), ensure_ascii=False, indent=2)
    else:
        output = _render_text(findings)
        if errors:
            output += "\n" + "\n".join(f"[ERRO] {error}" for error in errors)
    if args.format == "sarif":
        for error in errors:
            print(f"Erro: {error}", file=sys.stderr)
    try:
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
    except OSError:
        print("Erro: não foi possível gravar o relatório.", file=sys.stderr)
        return 2

    failed = args.fail_on != "none" and any(
        SEVERITY_ORDER[item["severity"]] >= SEVERITY_ORDER[args.fail_on] for item in findings
    )
    return 2 if errors else (1 if failed else 0)


if __name__ == "__main__":
    raise SystemExit(main())
