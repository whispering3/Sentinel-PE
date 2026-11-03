import type { EvidenceType, FindingCategory, Language, ResponseDecision, Severity } from '../types'

export const translations = {
  pt: {
    // Topbar & Navigation
    navGuard: 'Proteção Ativa',
    navScanner: 'Análise Estática',
    navQuarantine: 'Quarentena',
    statusActive: 'Escudo Ativo · Tempo Real',
    statusPaused: 'Escudo Pausado',
    statusOffline: 'Modo Análise Local',

    // Hero / Scanner Empty State
    eyebrow: 'PLATAFORMA DE DETECÇÃO EXPLICÁVEL & TRIAGEM PE',
    heroTitle1: 'Detecção explicável contra Ransomware,',
    heroTitle2: 'Infostealers e Ameaças PE.',
    heroLead:
      'Monitoramento reativo opt-in de pastas críticas, armadilhas Canary Anti-Ransomware, análise de indicadores de roubo de cookies/credenciais e engenharia reversa estática — 100% local.',
    btnSelectFile: '⬆ Analisar Arquivo (.exe / .dll)',
    btnScanFolder: '📂 Escanear Pasta',
    dropHint: 'Ou arraste qualquer executável Windows para esta janela',
    privacyNote: '100% Offline-First: Nenhum arquivo é enviado para servidores externos.',
    emptyReadyTitle: 'Pronto para inspeção profunda',
    emptyReadySub: 'Selecione uma amostra suspeita para extrair estrutura PE, indicadores de Ransomware, Infostealers e gerar regras YARA/Sigma.',
    loadingTitle: 'Desmontando binário e aplicando heurísticas…',
    loadingSub: 'Calculando hashes, verificando entropia, tabela de imports e assinaturas de ameaças.',
    dropOverlay: 'Solte o executável para análise imediata',

    // Active Guard Dashboard
    guardTitle: 'Escudo Reativo em Tempo Real (Modo Opt-In)',
    guardSubtitle: 'Monitoramento reativo opcional de pastas críticas e armadilha Canary. Toda quarentena (AES-256-GCM) ou encerramento exige confirmação explícita.',
    guardRealtimeToggle: 'Ativar Monitoramento Reativo de Pastas (Opt-In)',
    guardAutoBlockToggle: 'Política Segura: Quarentena Manual Criptografada (AES-256-GCM) com Confirmação Explícita',
    guardCanaryToggle: 'Ativar Armadilha Anti-Ransomware (Canary Honeypot Opt-In)',
    metricShield: 'Status do Escudo',
    metricShieldOn: 'PROTEGIDO',
    metricShieldOff: 'DESATIVADO',
    metricCanary: 'Honeypot Anti-Ransomware',
    metricCanaryIntact: 'ÍNTEGRO (Vigiando)',
    metricCanaryTampered: '🚨 VIOLADO (Ataque!)',
    metricCanaryOff: 'Desativado',
    metricScanned: 'Arquivos Inspecionados',
    metricBlocked: 'Ameaças Isoladas',
    watchedFoldersTitle: 'Zonas Monitoradas (Opt-In)',
    canaryFilesTitle: 'Arquivos-Isca (Canary Honeypots)',
    alertsTitle: 'Alertas de Segurança e Eventos',
    btnClearAlerts: 'Limpar Alertas',
    noAlerts: 'Nenhuma atividade maliciosa detectada nas pastas monitoradas.',
    processesTitle: 'Monitor de Processos Suspeitos em Execução',
    btnRefreshProcesses: '↻ Atualizar Processos',
    btnKillProcess: 'Encerrar (Kill)',
    btnKillAndQuarantine: 'Matar + Quarentenar',
    noSuspiciousProcesses: 'Nenhum processo suspeito rodando fora de diretórios seguros do sistema.',
    colPid: 'PID',
    colProcess: 'Processo',
    colPath: 'Caminho / Linha de Comando',
    colRisk: 'Risco / Motivo',
    colAction: 'Ação',

    // Quarantine Tab
    quarantineTitle: 'Cofre de Quarentena (AES-256-GCM)',
    quarantineSubtitle: 'Arquivos maliciosos isolados, criptografados (AES-256-GCM) e verificados por SHA-256 para impedir execução acidental.',
    noQuarantine: 'Nenhum arquivo em quarentena no momento.',
    btnRestore: 'Restaurar',
    btnDeletePerm: 'Excluir Definitivamente',
    btnQuarantineCurrent: '🔒 Enviar para Quarentena',
    colDate: 'Data',
    colFile: 'Arquivo Original',
    colCategory: 'Ameaça',
    colScore: 'Score',

    // Scanner Results
    sampleAnalyzed: 'AMOSTRA ANALISADA',
    btnNewAnalysis: 'Nova Análise',
    btnImportTelemetry: 'Importar Telemetria',
    btnPrintPdf: 'Imprimir / PDF',
    sessionHistory: 'Histórico da Sessão',
    riskScoreLabel: 'Score de Risco',
    confidenceLabel: 'Confiança Analítica',
    decisionLabel: 'Decisão Recomendada',
    riskLow: 'Baixo Risco',
    riskMedium: 'Atenção',
    riskHigh: 'Alto Risco',
    riskCritical: 'Crítico',

    // Rule Test Lab
    ruleLabTitle: 'Laboratório de Validação de Regras (YARA & Sigma)',
    ruleLabYaraOk: '✅ Sintaxe YARA Válida & Testada contra a Amostra',
    ruleLabSigmaOk: '✅ Esquema Sigma YAML & UUID v4 Válidos',

    // Behavioral Correlation
    correlationTitle: 'Motor de Correlação Comportamental (Sysmon / Telemetria)',
    correlationEmpty: 'Nenhuma cadeia multi-estágio correlacionada nos eventos importados.',

    // Threat Summary Cards
    cardRansomware: 'Risco de Ransomware',
    cardInfostealer: 'Roubo de Senhas / Cookies',
    cardInjection: 'Injeção / Evasão',
    statusDetected: 'INDICADORES DETECTADOS',
    statusClean: 'Nenhum indicador crítico',

    // Metrics
    labelArch: 'Arquitetura',
    labelSubsystem: 'Subsistema',
    labelEntryPoint: 'Entry Point',
    labelImageBase: 'Image Base',
    labelTimestamp: 'Compilação',
    labelSigned: 'Tabela WIN_CERTIFICATE',
    labelTls: 'TLS Callbacks',
    labelSize: 'Tamanho',
    yes: '✅ Sim',
    no: '❌ Ausente',
    yesWarn: '⚠️ Sim',
    noClean: 'Não',
    certUnverified: '⚠️ Presente (Não Verificado)',

    // Hashes & Comparator
    hashesTitle: 'Hashes Criptográficos & Clustering',
    hashComparePlaceholder: 'Cole um hash SHA-256 ou MD5 esperado para comparar…',
    hashMatch: '✅ Hash idêntico! O arquivo corresponde exatamente ao hash informado.',
    hashMismatch: '❌ Hash diferente! O arquivo NÃO corresponde ao hash informado.',

    // Findings
    findingsTitle: 'Achados Explicáveis (Capacidade vs. Indício vs. Contexto)',
    filterAll: 'Todos',
    noFindingsInCat: 'Nenhum achado nesta severidade.',

    // Sections & Mitigations
    sectionsTitle: 'Tabela de Seções PE',
    colSecName: 'Nome',
    colSecRva: 'RVA',
    colSecVirtual: 'Virtual',
    colSecRaw: 'Raw',
    colSecEntropy: 'Entropia',
    colSecFlags: 'Permissões',
    mitigationsTitle: 'Mitigações de Segurança do Binário',

    // Imports & Exports
    importsTitle: 'Tabela de Imports (APIs)',
    exportsTitle: 'Tabela de Exports',
    functionsCount: 'funções',
    btnFunctions: 'Funções',
    btnDlls: 'DLLs',
    searchFunctionsPlaceholder: 'Filtrar por nome de API ou DLL (ex: Crypt, VirtualAlloc, WinHttp)…',
    noImports: 'Nenhuma importação estática identificada.',
    noExports: 'Nenhuma função exportada.',
    showingTop: 'Mostrando primeiros',
    ofTotal: 'de',

    // Indicators & Strings
    indicatorsTitle: 'Indicadores de Comprometimento (IOCs)',
    stringsTitle: 'Strings Extraídas',
    searchStringsPlaceholder: 'Filtrar strings (ex: Cookie, Login Data, vssadmin, .onion, http)…',
    noStrings: 'Nenhuma string encontrada com este filtro.',
    telemetryTitle: 'Timeline de Evidências Externas (Sysmon / Sandbox)',
    telemetryEmpty: 'Importe eventos JSON (Sysmon Event IDs 1, 3, 8, 10, 11, 12–14, 22) exportados de um laboratório autorizado.',
    extraMetaTitle: 'Metadados Avançados (.NET CLR, Delay-Imports, Manifesto & Overlay)',
  },

  en: {
    // Topbar & Navigation
    navGuard: 'Active Guard',
    navScanner: 'Static Analyzer',
    navQuarantine: 'Quarantine',
    statusActive: 'Shield Active · Real-Time',
    statusPaused: 'Shield Paused',
    statusOffline: 'Local Analysis Mode',

    // Hero / Scanner Empty State
    eyebrow: 'EXPLAINABLE DETECTION & PE TRIAGE PLATFORM',
    heroTitle1: 'Explainable detection against Ransomware,',
    heroTitle2: 'Infostealers & PE Threats.',
    heroLead:
      'Opt-in reactive monitoring of high-risk folders, Anti-Ransomware Canary traps, credential & session cookie theft indicator analysis, and static reverse engineering — 100% local.',
    btnSelectFile: '⬆ Analyze Binary (.exe / .dll)',
    btnScanFolder: '📂 Scan Folder',
    dropHint: 'Or drag and drop any Windows executable anywhere into this window',
    privacyNote: '100% Offline-First: No files are ever uploaded to external servers.',
    emptyReadyTitle: 'Ready for deep inspection',
    emptyReadySub: 'Select a suspicious sample to inspect PE structure, Ransomware & Infostealer indicators, and generate YARA/Sigma rules.',
    loadingTitle: 'Dissecting binary & running heuristics…',
    loadingSub: 'Computing hashes, checking section entropy, import tables, and threat signatures.',
    dropOverlay: 'Drop executable for immediate analysis',

    // Active Guard Dashboard
    guardTitle: 'Reactive Endpoint Guard (Opt-In Mode)',
    guardSubtitle: 'Optional reactive folder monitoring and Canary trap. Every quarantine (AES-256-GCM) or process termination requires explicit confirmation.',
    guardRealtimeToggle: 'Enable Reactive Folder Monitoring (Opt-In)',
    guardAutoBlockToggle: 'Safe Policy: Manual Encrypted Quarantine (AES-256-GCM) with Explicit Confirmation',
    guardCanaryToggle: 'Enable Anti-Ransomware Trap (Canary Honeypot Opt-In)',
    metricShield: 'Shield Status',
    metricShieldOn: 'PROTECTED',
    metricShieldOff: 'DISABLED',
    metricCanary: 'Anti-Ransomware Honeypot',
    metricCanaryIntact: 'INTACT (Watching)',
    metricCanaryTampered: '🚨 TAMPERED (Attack!)',
    metricCanaryOff: 'Disabled',
    metricScanned: 'Files Inspected',
    metricBlocked: 'Threats Isolated',
    watchedFoldersTitle: 'Monitored Zones (Opt-In)',
    canaryFilesTitle: 'Decoy Files (Canary Honeypots)',
    alertsTitle: 'Security Alerts & Events',
    btnClearAlerts: 'Clear Alerts',
    noAlerts: 'No malicious activity detected in monitored folders.',
    processesTitle: 'Live Suspicious Process Monitor',
    btnRefreshProcesses: '↻ Refresh Processes',
    btnKillProcess: 'Terminate (Kill)',
    btnKillAndQuarantine: 'Kill + Quarantine',
    noSuspiciousProcesses: 'No suspicious processes running outside trusted system directories.',
    colPid: 'PID',
    colProcess: 'Process',
    colPath: 'Path / Command Line',
    colRisk: 'Risk / Reason',
    colAction: 'Action',

    // Quarantine Tab
    quarantineTitle: 'Quarantine Vault (AES-256-GCM)',
    quarantineSubtitle: 'Isolated, AES-256-GCM encrypted, and SHA-256 verified files prevented from accidental execution.',
    noQuarantine: 'No quarantined files at the moment.',
    btnRestore: 'Restore',
    btnDeletePerm: 'Delete Permanently',
    btnQuarantineCurrent: '🔒 Send to Quarantine',
    colDate: 'Date',
    colFile: 'Original File',
    colCategory: 'Threat',
    colScore: 'Score',

    // Scanner Results
    sampleAnalyzed: 'ANALYZED SAMPLE',
    btnNewAnalysis: 'New Analysis',
    btnImportTelemetry: 'Import Telemetry',
    btnPrintPdf: 'Print / PDF',
    sessionHistory: 'Session History',
    riskScoreLabel: 'Risk Score',
    confidenceLabel: 'Analytical Confidence',
    decisionLabel: 'Recommended Decision',
    riskLow: 'Low Risk',
    riskMedium: 'Caution',
    riskHigh: 'High Risk',
    riskCritical: 'Critical',

    // Rule Test Lab
    ruleLabTitle: 'Detection Rule Test Lab (YARA & Sigma)',
    ruleLabYaraOk: '✅ YARA Syntax Valid & Self-Tested Against Sample',
    ruleLabSigmaOk: '✅ Sigma YAML Schema & UUID v4 Valid',

    // Behavioral Correlation
    correlationTitle: 'Behavioral Correlation Engine (Sysmon / Telemetry)',
    correlationEmpty: 'No multi-stage behavioral chains correlated in imported events.',

    // Threat Summary Cards
    cardRansomware: 'Ransomware Risk',
    cardInfostealer: 'Credential / Cookie Theft',
    cardInjection: 'Injection / Evasion',
    statusDetected: 'INDICATORS DETECTED',
    statusClean: 'No critical indicators',

    // Metrics
    labelArch: 'Architecture',
    labelSubsystem: 'Subsystem',
    labelEntryPoint: 'Entry Point',
    labelImageBase: 'Image Base',
    labelTimestamp: 'Compile Time',
    labelSigned: 'WIN_CERTIFICATE Table',
    labelTls: 'TLS Callbacks',
    labelSize: 'File Size',
    yes: '✅ Yes',
    no: '❌ Absent',
    yesWarn: '⚠️ Yes',
    noClean: 'No',
    certUnverified: '⚠️ Present (Unverified)',

    // Hashes & Comparator
    hashesTitle: 'Cryptographic Hashes & Clustering',
    hashComparePlaceholder: 'Paste an expected SHA-256 or MD5 hash to verify…',
    hashMatch: '✅ Exact Match! File hash matches the provided value.',
    hashMismatch: '❌ Hash Mismatch! File does NOT match the provided value.',

    // Findings
    findingsTitle: 'Explainable Findings (Capability vs. Indicator vs. Context)',
    filterAll: 'All',
    noFindingsInCat: 'No findings in this severity level.',

    // Sections & Mitigations
    sectionsTitle: 'PE Section Table',
    colSecName: 'Name',
    colSecRva: 'RVA',
    colSecVirtual: 'Virtual',
    colSecRaw: 'Raw',
    colSecEntropy: 'Entropy',
    colSecFlags: 'Permissions',
    mitigationsTitle: 'Binary Security Mitigations',

    // Imports & Exports
    importsTitle: 'Import Table (APIs)',
    exportsTitle: 'Export Table',
    functionsCount: 'functions',
    btnFunctions: 'Functions',
    btnDlls: 'DLLs',
    searchFunctionsPlaceholder: 'Filter by API or DLL name (e.g. Crypt, VirtualAlloc, WinHttp)…',
    noImports: 'No static imports identified.',
    noExports: 'No exported functions.',
    showingTop: 'Showing top',
    ofTotal: 'of',

    // Indicators & Strings
    indicatorsTitle: 'Extracted Indicators (IOCs)',
    stringsTitle: 'Extracted Strings',
    searchStringsPlaceholder: 'Filter strings (e.g. Cookie, Login Data, vssadmin, .onion, http)…',
    noStrings: 'No strings matching filter.',
    telemetryTitle: 'External Evidence Timeline (Sysmon / Sandbox)',
    telemetryEmpty: 'Import JSON events (Sysmon Event IDs 1, 3, 8, 10, 11, 12–14, 22) exported from an authorized lab.',
    extraMetaTitle: 'Advanced Metadata (.NET CLR, Delay-Imports, Manifest & Overlay)',
  },
} as const

export const evidenceTypeLabels: Record<Language, Record<EvidenceType, string>> = {
  pt: {
    capability: 'Capacidade',
    indicator: 'Indício',
    context: 'Contexto',
    observed: 'Observado',
  },
  en: {
    capability: 'Capability',
    indicator: 'Indicator',
    context: 'Context',
    observed: 'Observed',
  },
}

export const decisionLabels: Record<Language, Record<ResponseDecision, string>> = {
  pt: {
    observe: 'OBSERVAR (Revisão Manual)',
    alert: 'ALERTAR (Investigar Evidências)',
    block: 'ISOLAR / QUARENTENA RECOMENDADA',
  },
  en: {
    observe: 'OBSERVE (Manual Review)',
    alert: 'ALERT (Investigate Evidence)',
    block: 'ISOLATE / QUARANTINE RECOMMENDED',
  },
}

export const severityLabels: Record<Language, Record<Severity, string>> = {
  pt: {
    critical: 'crítico',
    high: 'alto',
    medium: 'médio',
    low: 'baixo',
    informational: 'info',
  },
  en: {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    informational: 'info',
  },
}

export const categoryLabels: Record<Language, Record<FindingCategory, string>> = {
  pt: {
    ransomware: 'Ransomware',
    infostealer: 'Roubo de Dados / Cookies',
    packer: 'Packer / Ofuscação',
    injection: 'Injeção de Processo',
    persistence: 'Persistência',
    evasion: 'Anti-Análise / Evasão',
    'privilege-escalation': 'Escalação de Privilégio',
    network: 'Rede / C2',
    general: 'Estrutura PE',
  },
  en: {
    ransomware: 'Ransomware',
    infostealer: 'Infostealer / Cookies',
    packer: 'Packer / Obfuscation',
    injection: 'Process Injection',
    persistence: 'Persistence',
    evasion: 'Anti-Analysis / Evasion',
    'privilege-escalation': 'Privilege Escalation',
    network: 'Network / C2',
    general: 'PE Hardening',
  },
}

export const ruleTitleTranslationsPt: Record<string, string> = {
  // Ransomware
  'Shadow Copy Deletion Command': 'Comando de Exclusão de Cópias de Sombra (Shadow Copies)',
  'Boot Recovery Sabotage': 'Sabotagem de Recuperação de Boot (bcdedit)',
  'Cryptography API + File Enumeration Combo (Ransomware Pattern)': 'APIs de Criptografia + Varredura de Arquivos (Padrão de Ransomware)',
  'Tor Hidden Service Address (.onion)': 'Endereço de Comando e Controle na Rede Tor (.onion)',
  'Ransom Note / Extortion Language': 'Linguagem de Nota de Resgate / Extorsão Detectada',
  'Cryptography APIs Imported': 'Importação de APIs de Criptografia de Arquivos',
  'Network Drive Enumeration (Worm/Ransomware Propagation)': 'Enumeração de Unidades de Rede (Propagação Lateral)',
  'Known Ransomware File Extension Patterns': 'Extensões de Arquivos de Ransomware Conhecidos',

  // Infostealer (Credentials & Cookies)
  'Browser Session Cookie & Credential Store Targeting (Infostealer)': 'Alvo em Cookies de Sessão e Senhas de Navegadores (Infostealer)',
  'LSASS / SAM Credential Dumping Indicators': 'Indicadores de Dump de Credenciais de Memória (LSASS / SAM)',
  'Windows DPAPI & Credential Vault Extraction': 'Extração de Senhas via Windows DPAPI / Cofre de Credenciais',
  'Session Token & Messenger Account Hijacking (Discord / Telegram / Steam)': 'Roubo de Tokens de Sessão (Discord / Telegram / Steam)',
  'Cryptocurrency Wallet & Browser Extension Theft': 'Roubo de Carteiras Cripto e Extensões (MetaMask / Phantom / Exodus)',
  'Keystroke & Clipboard Hijacking APIs (Keylogger / Clipper)': 'Captura de Teclado e Área de Transferência (Keylogger / Clipper)',

  // Packer
  'High-Entropy Executable Section (Packed / Encrypted Payload)': 'Seção Executável com Alta Entropia (Payload Criptografado / Packer)',
  'High-Entropy Data Section': 'Seção de Dados com Entropia Elevada',
  'Known Packer / Protector Section Name': 'Nome de Seção de Packer / Protetor Conhecido',
  'Only GetProcAddress / LoadLibrary Imports (Dynamic API Resolution)': 'Apenas GetProcAddress / LoadLibrary (Resolução Dinâmica de APIs)',
  'File Overlay Detected (Data After Last Section)': 'Overlay Detectado (Dados Ocultos Após a Última Seção)',
  'No Static Imports (Likely Packed / Statically Linked)': 'Sem Imports Estáticos (Provável Binário Empacotado)',

  // Injection
  'Classic Remote Process Injection APIs': 'APIs Clássicas de Injeção Remota em Processos',
  'DLL Injection via SetWindowsHookEx': 'Injeção de DLL / Hook Global via SetWindowsHookEx',
  'Process Hollowing (Unmap + Rewrite)': 'Process Hollowing (Desmapeamento de Seção)',
  'Shared Memory / Fileless Injection APIs': 'Injeção Fileless / Memória Compartilhada',
  'APC Injection (QueueUserAPC)': 'Injeção de Código via Fila APC (QueueUserAPC)',

  // Persistence
  'Registry Run Key / Startup Persistence': 'Persistência em Chaves de Inicialização do Registro (Run / Winlogon)',
  'Windows Service Installation': 'Instalação ou Modificação de Serviço do Windows',
  'Scheduled Task Strings': 'Manipulação de Tarefas Agendadas (Scheduled Tasks)',

  // Privilege Escalation
  'Token Privilege Manipulation': 'Manipulação de Tokens de Privilégio do Sistema',
  'SeDebugPrivilege Reference': 'Referência a SeDebugPrivilege (Acesso Total a Processos)',
  'Known UAC Bypass Pattern': 'Padrão Conhecido de Bypass de UAC',

  // Evasion
  'Debugger Detection APIs': 'APIs de Detecção de Debugger (Anti-Engenharia Reversa)',
  'VM / Sandbox Fingerprinting': 'Detecção de Máquina Virtual / Sandbox',
  'Timing-Based Anti-Sandbox (Sleep + Query)': 'Evasão de Sandbox por Atraso de Tempo (Timing Check)',
  'TLS Callbacks (Pre-EntryPoint Code Execution)': 'TLS Callbacks Presentes (Execução Antes do Entry Point)',

  // Network
  'Reverse Shell Pattern (Socket + Process Creation)': 'Padrão de Reverse Shell (Conexão de Rede + Execução de Processo)',
  'DNS Lookup + HTTP (Potential C2 Beacon)': 'Comunicação de Rede HTTP + DNS (Potencial Beacon C2)',

  // General
  'Executable + Writable Section (W^X Violation)': 'Seção Simultaneamente Executável e Gravável (Violação W^X)',
  'No ASLR (DYNAMIC_BASE not set)': 'Binário sem ASLR (Endereço Base Fixo)',
  'No DEP / NX (NX_COMPAT not set)': 'Binário sem Proteção DEP / NX',
  'Not Authenticode Signed': 'Binário Sem Assinatura Digital Authenticode',
  'PDB Debug Path Exposed': 'Caminho de Debug PDB Exposto',
  'Section Virtual vs. Raw Size Discrepancy (Unpacking Stub)': 'Discrepância de Tamanho Virtual vs. Raw na Seção (Stub de Unpacking)',
  'Manifest Requests Administrator Elevation': 'Manifesto Embutido Solicita Elevação de Administrador (requireAdministrator)',
  '.NET Managed Assembly (CLR Header Present)': 'Assembly Gerenciado .NET (Cabeçalho CLR Presente)',
  'Static Analysis Only — Lab Validation Required': 'Triagem Estática Concluída — Verifique o Escopo do Alvo',
}

export function translateRuleTitle(title: string, lang: Language): string {
  if (lang === 'en') return title
  return ruleTitleTranslationsPt[title] ?? title
}

