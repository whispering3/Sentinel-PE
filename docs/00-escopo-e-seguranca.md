# Escopo e Arquitetura de Segurança

## Finalidade

O **Sentinel PE** é uma bancada defensiva local-first para triagem estática de executáveis Windows (PE32/PE32+), detecção heurística de **Ransomware** e **Infostealers** (roubo de cookies de sessão, credenciais DPAPI, tokens e carteiras), geração de regras YARA/Sigma e monitoramento ativo opcional (*opt-in*).

## Controles de Segurança da Aplicação

1. **Análise 100% Local e Sem Execução:**
   - O parser PE inspeciona os bytes do arquivo de forma estática com limites estritos de memória e verificação de bordas (`DataView` bounds checking) contra binários malformados.
   - A aplicação jamais executa o binário analisado.
2. **Monitoramento Ativo Opt-In:**
   - O monitoramento de pastas críticas (`Downloads`, `Desktop`, `Temp`) e a armadilha Canary Anti-Ransomware iniciam **desativados por padrão**, sendo ativados somente por escolha explícita do usuário (*opt-in*).
3. **Quarentena Manual, Reversível e com Confirmação Explícita:**
   - O Sentinel PE não exclui nem move arquivos silenciosamente em segundo plano.
   - Toda ação de quarentena, restauração, exclusão permanente ou encerramento de processo exige **confirmação explícita em diálogo nativo do sistema operacional**.
   - A quarentena verifica o hash `SHA-256` antes de remover o arquivo original e ao restaurá-lo, garantindo reversibilidade integral e bloqueando alterações em pastas protegidas do sistema (`C:\Windows`, `Program Files`).
4. **Isolamento de IPC no Electron:**
   - `contextIsolation: true`, `nodeIntegration: false` e `sandbox: true`.
   - Todos os canais IPC sensíveis validam estritamente o `sender`, o `mainFrame` e a origem local confiável (`dist/index.html`), bloqueando navegações externas ou chamadas de subframes.

## Limites do Repositório

Não publique neste repositório:
- ransomware, criptografadores de arquivos ou mecanismos de extorsão;
- código de persistência ofensiva, evasão ou propagação operacional;
- amostras executáveis maliciosas, senhas, chaves privadas ou dados de vítimas.
