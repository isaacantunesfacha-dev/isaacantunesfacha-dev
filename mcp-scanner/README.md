# MCP Scanner

Scanner local e offline de configurações de clientes MCP. Ele identifica padrões de risco em arquivos JSON sem iniciar servidores, acessar rede ou executar comandos.

## Uso

Requer Python 3.10+ e usa somente a biblioteca padrão. A partir da raiz do repositório:

```bash
python3 mcp-scanner/mcp_scanner.py caminho/para/config.json
```

O comando retorna `0` quando não encontra achados, `1` quando encontra riscos e `2` quando não consegue ler ou validar o arquivo. Os achados são enviados em JSON para stdout; erros vão para stderr. Não passe arquivos com segredos: valores de ambiente e argumentos são deliberadamente omitidos do relatório.

## Verificações iniciais

- Servidor configurado para executar via `npx` ou `uvx`, que pode baixar código no primeiro uso.
- Transporte remoto sem TLS (`http://`).
- Cabeçalhos de autenticação declarados inline em vez de referências a variáveis de ambiente.
- Variáveis de ambiente inline com nomes potencialmente sensíveis.
- Caminhos locais relativos, que podem resolver para executáveis inesperados dependendo do diretório atual.

Este MVP faz análise estática heurística: não prova explorabilidade, não verifica a confiabilidade de pacotes e pode gerar falsos positivos. Não é uma auditoria de segurança completa.

## Testes

```bash
python3 -m unittest discover -s mcp-scanner/tests -v
```

## Limites de segurança

O scanner lê apenas o arquivo indicado, não segue links simbólicos explicitamente, não faz chamadas de rede e não executa configurações encontradas. Mantenha tokens e credenciais fora dos arquivos compartilhados.
