# Roteiro de Validação Ponta a Ponta no PC Secundário (Windows 10/11 x64)

Este roteiro valida todos os módulos do **Sentinel PE v0.3.0** na máquina secundária ou VM de laboratório usando os executáveis empacotados em `release/`.

---

## Artefatos de Instalação / Execução (`release/`)

- **Portátil (sem instalação):** `Sentinel PE-0.3.0-portable-x64.exe`
- **Instalador NSIS:** `Sentinel PE-Setup-0.3.0-x64.exe`
- **Pacote ZIP x64:** `sentinel-pe-0.3.0-win.zip`
- **Checksums:** `SHA256SUMS.txt`

---

## Checklist de Testes Ponta a Ponta

### 1. Interface e Alternância de Idioma (PT-BR / EN)
- [ ] Abra o executável `Sentinel PE` no PC secundário.
- [ ] Alterne o seletor **PT | EN** no canto superior direito e confirme que as abas, botões, métricas e filtros mudam de idioma instantaneamente.
- [ ] Verifique que o **Monitoramento em Tempo Real** e a **Armadilha Canary** iniciam **desativados por padrão (Modo Opt-In)**.

### 2. Parser PE e Resiliência a Arquivos Malformados
- [ ] Na aba **Análise Estática**, selecione `C:\Windows\System32\notepad.exe` (ou `calc.exe`).
- [ ] Confirme a extração de:
  - Arquitetura `x64 (AMD64)`, Subsistema, Entry Point e Image Base.
  - Hashes `SHA-256` (64 hex), `SHA-1` (40 hex), `MD5` (32 hex) e `ImpHash` (32 hex).
  - Tabela de Seções com entropia e flags (`CODE`, `EXECUTE`, `READ`).
  - Tabela de Imports por função e por DLL, Tabela de Exports e Mitigações (`DYNAMIC_BASE`, `NX_COMPAT`, `GUARD_CF`).
  - Strings ASCII e Unicode (`UTF-16LE`).
- [ ] Cole o hash SHA-256 exibido no campo de comparação de hashes e confirme a mensagem de correspondência exata (`✅ Hash idêntico`).
- [ ] Selecione um arquivo de texto comum renomeado ou não-PE (`.txt` / `.jpg`) e confirme que o parser exibe erro controlado (`O arquivo não possui assinatura MZ válida`) sem travar a interface.

### 3. Exportação e Validação de Regras (YARA, Sigma, JSON, Markdown)
- [ ] Clique nos botões **JSON**, **Markdown**, **YARA** e **Sigma**.
- [ ] Abra o arquivo `.yara` exportado e confirme:
  - Identificador válido (`rule Sentinel_PE_...`).
  - Strings devidamente escapadas (sem quebras de linha literais ou aspas não escapadas).
  - Condição consistente (não referencia `$api_*` ou `$str_*` se não existirem no bloco `strings:`).
- [ ] Abra o arquivo `.sigma.yml` exportado e confirme:
  - Campo `id:` contém um UUID v4 determinístico válido (nunca `00000000-0000-0000-0000-000000000000`).
  - Bloco `Hashes|contains` não emite entradas vazias (`IMPHASH=` só aparece quando o binário possui imports).

### 4. Monitoramento Ativo Opt-In e Armadilha Canary
- [ ] Na aba **Proteção Ativa**, marque a opção **Ativar Monitoramento de Pastas em Tempo Real (Opt-In)**.
- [ ] Confirme que as pastas `Downloads`, `Desktop` e `Temp` aparecem listadas como vigiadas e o status muda para **PROTEGIDO**.
- [ ] Marque **Ativar Armadilha Anti-Ransomware (Canary Honeypot Opt-In)** e confirme que os arquivos-isca são criados com status **ÍNTEGRO**.
- [ ] Clique em **↻ Atualizar Processos** no Monitor de Processos Suspeitos e verifique a listagem.

### 5. Quarentena Manual, Confirmação Explícita e Restauração Reversível
- [ ] Crie uma cópia de um executável de teste em uma pasta de usuário (ex: copie `C:\Windows\System32\notepad.exe` para `C:\Users\<Usuario>\Downloads\teste_amostra.exe`).
- [ ] Analise `teste_amostra.exe` na aba **Análise Estática** e anote seu `SHA-256`.
- [ ] Clique em **🔒 Enviar para Quarentena**.
- [ ] Confirme que o **diálogo nativo de confirmação explícita** é exibido mostrando o caminho completo do arquivo e aguarda sua confirmação.
- [ ] Clique em **Confirmar Quarentena**:
  - Verifique que `teste_amostra.exe` foi removido da pasta `Downloads` e movido para o Cofre de Quarentena.
- [ ] Acesse a aba **🔒 Quarentena**:
  - Clique em **Restaurar** no item `teste_amostra.exe` e confirme no diálogo explícito.
  - Verifique que `teste_amostra.exe` voltou exatamente para `Downloads` com o **mesmo hash SHA-256** original.
- [ ] Confirme também que arquivos em `C:\Windows\System32` são recusados caso alguém tente quarentená-los.
