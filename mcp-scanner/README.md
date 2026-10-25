# MCP Scanner

Scanner local e offline de configurações de clientes MCP. Ele identifica padrões de risco em arquivos JSON sem iniciar servidores, acessar rede ou executar comandos.

## Uso

Requer Python 3.9+ e não tem dependências de runtime. A instalação do pacote usa setuptools como backend de build. A partir da raiz do repositório:

```bash
python3 -m pip install ./mcp-scanner
mcp-sec scan caminho/para/config.json --fail-on high --format sarif --output mcp-sec.sarif
```

O comando retorna `0` quando nenhum achado alcança o limiar, `1` quando alcança e `2` quando não consegue ler, validar ou gravar. `--fail-on` aceita `critical`, `high`, `medium`, `low` e `none` (padrão: `low`). `--format` aceita `json`, `text` e `sarif`; `--output` grava o relatório no caminho indicado e o substitui se já existir. Sem `--output`, o relatório vai para stdout e erros para stderr. Cada achado inclui mensagem e recomendação de correção.

Os relatórios omitem valores, argumentos, nomes originais de servidores, nomes de variáveis sensíveis e valores de cabeçalhos. O SARIF 2.1.0 aponta ao arquivo de configuração sem linha específica; GitHub Code Scanning exige ao menos uma localização para exibir um alerta, mas localização de linha é necessária para anotação precisa no código. Para localização útil no GitHub, rode a CLI da raiz do checkout e passe caminhos dentro do repositório. O envio para GitHub ainda não está configurado.

Mesmo com os valores removidos, relatórios podem revelar caminhos e classes de riscos. Em repositórios públicos, não versione arquivos reais de configuração MCP nem relatórios gerados a partir de ambientes privados; use fixtures sintéticas e um gerenciador de segredos. Consulte [SARIF suportado pelo GitHub](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

## Verificações iniciais

- Servidor configurado para executar via `npx` ou `uvx`, que pode baixar código no primeiro uso.
- Transporte remoto sem TLS (`http://`).
- Cabeçalhos de autenticação declarados inline em vez de referências a variáveis de ambiente.
- Variáveis de ambiente inline com nomes potencialmente sensíveis.
- Caminhos locais relativos, que podem resolver para executáveis inesperados dependendo do diretório atual.

Este MVP faz análise estática heurística: não prova explorabilidade, não verifica a confiabilidade de pacotes e pode gerar falsos positivos. Não é uma auditoria de segurança completa.

## Testes

A suíte usa somente fixtures sintéticas em `tests/fixtures/` (um exemplo sem achados e outro com riscos conhecidos).

```bash
python3 -m unittest discover -s mcp-scanner/tests -v
```

## Limites de segurança

O scanner lê apenas o arquivo indicado, não segue links simbólicos explicitamente, não faz chamadas de rede e não executa configurações encontradas. Mantenha tokens e credenciais fora dos arquivos compartilhados.
