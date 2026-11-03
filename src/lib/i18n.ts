import type { EvidenceType, FindingCategory, Language, ResponseDecision, Severity } from '../types'

export const translations = {
  pt: {
    // Topbar & Navigation
    navGuard: 'Central de Proteção',
    navScanner: 'Inspetor Estático PE',
    navQuarantine: 'Cofre de Quarentena',
    statusActive: 'Monitoramento Ativo',
    statusPaused: 'Modo Sob Demanda',
    statusOffline: 'Motor Offline Local',

    // Scanner Empty State (Forensic Dropzone)
    eyebrow: 'MOTOR DE ANÁLISE ESTÁTICA & TRIAGEM FORENSE',
    heroTitle1: 'Inspeção Profunda de Executáveis Windows',
    heroTitle2: 'PE32 / PE32+ (.exe, .dll, .sys, .scr)',
    heroLead:
      'Arraste e solte um binário suspeito nesta área ou selecione um arquivo do disco para desmontar cabeçalhos PE, avaliar indicadores de Ransomware e Infostealers e gerar regras YARA/Sigma.',
    btnSelectFile: 'Selecionar Arquivo (.exe / .dll)',
    btnScanFolder: 'Escanear Diretório',
    dropHint: 'Suporta PE32 (x86), PE32+ (x64), DLLs, Drivers (.sys) e Control Panel Applets (.cpl)',
    privacyNote: 'Processamento 100% local e isolado: nenhum byte é transmitido para a nuvem.',
    emptyReadyTitle: 'Especificações do Motor Estático',
    emptyReadySub: 'Extração determinística de cabeçalhos COFF/Optional, entropia de Shannon por seção, ImpHash, Rich Header, strings ASCII/UTF-16LE e 37+ heurísticas explicáveis.',
    loadingTitle: 'Processando estrutura binária e aplicando heurísticas…',
    loadingSub: 'Calculando hashes criptográficos, entropia de seções, tabela de imports e assinaturas.',
    dropOverlay: 'Solte o executável para iniciar a análise estática',

    // Scanner Sub-tabs
    subTabOverview: 'Achados & Hashes',
    subTabStructure: 'Estrutura PE & Seções',
    subTabImports: 'Imports & Exports',
    subTabStrings: 'Strings & IOCs',
    subTabRules: 'YARA / Sigma & Telemetria',
    subTabAll: 'Relatório Completo',

    // Active Guard Dashboard
    guardTitle: 'Central de Proteção & Antivírus',
    guardSubtitle: 'Monitoramento reativo de pastas críticas, varreduras sob demanda com controle Start/Stop e armadilha Canary Anti-Ransomware.',
    guardBannerActiveTitle: 'Proteção Ativa em Tempo Real Operando',
    guardBannerActiveDesc: 'O motor está monitorando automaticamente as pastas críticas (Downloads, Desktop, Temp) contra novos executáveis e scripts suspeitos.',
    guardBannerIdleTitle: 'Monitoramento em Tempo Real Pausado',
    guardBannerIdleDesc: 'Clique em "Iniciar Proteção" para vigiar pastas críticas continuamente ou execute uma Varredura Rápida abaixo.',
    guardBannerAlertTitle: 'Alerta Crítico: Violação de Honeypot Canary Detectada',
    guardBannerAlertDesc: 'Um arquivo-isca Anti-Ransomware foi modificado ou removido. Verifique imediatamente os alertas e processos abaixo.',
    btnStartShield: 'Iniciar Proteção',
    btnStopShield: 'Parar Proteção',
    btnStartQuickScan: 'Iniciar Varredura Rápida',
    btnStartCustomScan: 'Selecionar Pasta e Escanear',
    btnStopScan: 'Parar Varredura',
    scanCenterTitle: 'Central de Varredura Antivírus',
    scanQuickTitle: 'Varredura Rápida (Zonas Críticas)',
    scanQuickDesc: 'Verifica executáveis e scripts em Downloads, Área de Trabalho e pasta Temp do usuário.',
    scanCustomTitle: 'Varredura de Pasta Personalizada',
    scanCustomDesc: 'Selecione qualquer pasta, pendrive ou diretório específico para inspeção profunda recursiva.',
    scanBinaryTitle: 'Análise Forense de Executável (.exe / .dll)',
    scanBinaryDesc: 'Desmonta cabeçalhos PE, calcula entropia, extrai strings/IOCs e valida regras YARA e Sigma.',
    scanRunningTitle: 'Varredura em Andamento…',
    scanCompletedTitle: 'Última Varredura Concluída',
    scanAbortedTitle: 'Varredura Interrompida pelo Usuário',
    scanCurrentFileLabel: 'Inspecionando arquivo:',
    guardRealtimeToggle: 'Monitoramento Contínuo de Pastas (Downloads, Desktop, Temp)',
    guardAutoBlockToggle: 'Cofre Transacional AES-256-GCM com Confirmação Manual Obrigatória',
    guardCanaryToggle: 'Armadilha Anti-Ransomware (Arquivos-Isca Canary Honeypot)',
    metricShield: 'Estado do Motor',
    metricShieldOn: 'ATIVO (TEMPO REAL)',
    metricShieldOff: 'SOB DEMANDA',
    metricCanary: 'Honeypot Anti-Ransomware',
    metricCanaryIntact: 'ÍNTEGRO (MONITORANDO)',
    metricCanaryTampered: 'VIOLADO (ALERTA CRÍTICO)',
    metricCanaryOff: 'DESATIVADO',
    metricScanned: 'Arquivos Inspecionados',
    metricBlocked: 'Ameaças Isoladas',
    watchedFoldersTitle: 'Diretórios Monitorados',
    canaryFilesTitle: 'Arquivos-Isca (Canary Honeypots)',
    alertsTitle: 'Registro de Alertas e Eventos de Segurança',
    btnClearAlerts: 'Limpar Registro',
    noAlerts: 'Nenhum evento suspeito registrado nas zonas monitoradas.',
    processesTitle: 'Processos Suspeitos em Execução (Fora de Diretórios do Sistema)',
    btnRefreshProcesses: 'Atualizar Lista',
    btnKillProcess: 'Encerrar Processo',
    btnKillAndQuarantine: 'Encerrar + Quarentenar',
    noSuspiciousProcesses: 'Nenhum processo suspeito detectado fora dos diretórios padrão do sistema.',
    colPid: 'PID',
    colProcess: 'Processo',
    colPath: 'Caminho / Linha de Comando',
    colRisk: 'Classificação / Motivo',
    colAction: 'Ações',

    // Quarantine Tab
    quarantineTitle: 'Cofre de Quarentena Criptografado',
    quarantineSubtitle: 'Arquivos isolados com criptografia autenticada AES-256-GCM, proteção anti-symlink e verificação de integridade SHA-256.',
    noQuarantine: 'Nenhum arquivo isolado no cofre de quarentena.',
    btnRestore: 'Restaurar Arquivo',
    btnDeletePerm: 'Excluir Permanentemente',
    btnQuarantineCurrent: 'Isolar em Quarentena',
    colDate: 'Data / Hora',
    colFile: 'Arquivo / Caminho Original',
    colCategory: 'Classificação',
    colScore: 'Risco',

    // Scanner Results
    sampleAnalyzed: 'RELATÓRIO DE INSPEÇÃO FORENSE PE',
    btnNewAnalysis: 'Analisar Outro Arquivo',
    btnImportTelemetry: 'Importar Telemetria',
    btnPrintPdf: 'Exportar PDF / Imprimir',
    sessionHistory: 'Arquivos Recentes na Sessão',
    riskScoreLabel: 'Score de Risco',
    confidenceLabel: 'Confiança Analítica',
    decisionLabel: 'Recomendação Operacional',
    riskLow: 'Baixo Risco',
    riskMedium: 'Risco Moderado',
    riskHigh: 'Alto Risco',
    riskCritical: 'Risco Crítico',

    // Rule Test Lab
    ruleLabTitle: 'Laboratório de Validação de Regras (YARA & Sigma)',
    ruleLabYaraOk: 'Sintaxe YARA validada e testada contra a amostra atual',
    ruleLabSigmaOk: 'Esquema Sigma YAML e UUID v4 determinístico validados',

    // Behavioral Correlation
    correlationTitle: 'Correlação Comportamental Multi-Estágio (Sysmon / Telemetria)',
    correlationEmpty: 'Nenhuma cadeia comportamental multi-estágio correlacionada nos eventos importados.',

    // Threat Summary Cards
    cardRansomware: 'Indicadores de Ransomware',
    cardInfostealer: 'Infostealer / Credenciais & Cookies',
    cardInjection: 'Injeção de Processo & Evasão',
    statusDetected: 'DETECTADO',
    statusClean: 'Não detectado',

    // Metrics
    labelArch: 'Arquitetura',
    labelSubsystem: 'Subsistema',
    labelEntryPoint: 'Entry Point',
    labelImageBase: 'Image Base',
    labelTimestamp: 'Data de Compilação',
    labelSigned: 'Tabela WIN_CERTIFICATE',
    labelTls: 'TLS Callbacks',
    labelSize: 'Tamanho do Arquivo',
    yes: 'Sim',
    no: 'Ausente',
    yesWarn: 'Presente (Atenção)',
    noClean: 'Ausente',
    certUnverified: 'Presente (Não Verificado)',

    // Hashes & Comparator
    hashesTitle: 'Assinaturas Criptográficas & Comparador de Hash',
    hashComparePlaceholder: 'Insira um hash SHA-256, SHA-1 ou MD5 para verificação imediata…',
    hashMatch: 'Correspondência exata confirmada com o hash informado.',
    hashMismatch: 'Divergência detectada: o arquivo não corresponde ao hash informado.',

    // Findings
    findingsTitle: 'Matriz de Evidências Estáticas e Heurísticas',
    filterAll: 'Todos',
    noFindingsInCat: 'Nenhum achado registrado para os filtros selecionados.',

    // Sections & Mitigations
    sectionsTitle: 'Tabela de Seções PE',
    colSecName: 'Seção',
    colSecRva: 'RVA',
    colSecVirtual: 'Tam. Virtual',
    colSecRaw: 'Tam. Raw',
    colSecEntropy: 'Entropia (0–8)',
    colSecFlags: 'Permissões',
    mitigationsTitle: 'Mitigações de Exploração e Hardening',

    // Imports & Exports
    importsTitle: 'Tabela de Importação (IAT)',
    exportsTitle: 'Tabela de Exportação (EAT)',
    functionsCount: 'APIs',
    btnFunctions: 'Funções',
    btnDlls: 'Bibliotecas (DLLs)',
    searchFunctionsPlaceholder: 'Pesquisar função ou biblioteca (ex: Crypt, VirtualAlloc, WinHttp)…',
    noImports: 'Nenhuma função importada estaticamente.',
    noExports: 'Nenhuma função exportada por este binário.',
    showingTop: 'Exibindo primeiros',
    ofTotal: 'de',

    // Indicators & Strings
    indicatorsTitle: 'Indicadores Extraídos (IOCs)',
    stringsTitle: 'Inspetor de Strings (ASCII & UTF-16LE)',
    searchStringsPlaceholder: 'Pesquisar strings (ex: Cookie, Login Data, vssadmin, .onion, http)…',
    noStrings: 'Nenhuma string corresponde ao filtro atual.',
    telemetryTitle: 'Timeline de Telemetria Externa (Sysmon / Sandbox)',
    telemetryEmpty: 'Importe um arquivo JSON contendo eventos Sysmon (IDs 1, 3, 8, 10, 11, 12–14, 22) para correlação comportamental.',
    extraMetaTitle: 'Metadados Estendidos (.NET CLR, Delay-Imports, Manifesto UAC & Overlay)',
  },

  en: {
    // Topbar & Navigation
    navGuard: 'Protection Center',
    navScanner: 'PE Static Inspector',
    navQuarantine: 'Quarantine Vault',
    statusActive: 'Real-Time Active',
    statusPaused: 'On-Demand Mode',
    statusOffline: 'Local Offline Engine',

    // Scanner Empty State (Forensic Dropzone)
    eyebrow: 'STATIC ANALYSIS & FORENSIC TRIAGE ENGINE',
    heroTitle1: 'Deep Inspection for Windows Executables',
    heroTitle2: 'PE32 / PE32+ (.exe, .dll, .sys, .scr)',
    heroLead:
      'Drag and drop a suspicious binary into the inspection bay or select a file from disk to dissect PE headers, evaluate Ransomware and Infostealer indicators, and generate YARA/Sigma rules.',
    btnSelectFile: 'Select Binary (.exe / .dll)',
    btnScanFolder: 'Scan Directory',
    dropHint: 'Supports PE32 (x86), PE32+ (x64), DLLs, Kernel Drivers (.sys), and Control Panel Applets (.cpl)',
    privacyNote: '100% local offline processing: zero bytes are ever uploaded to external servers.',
    emptyReadyTitle: 'Static Engine Specifications',
    emptyReadySub: 'Deterministic extraction of COFF/Optional headers, per-section Shannon entropy, ImpHash, Rich Header, ASCII/UTF-16LE strings, and 37+ explainable heuristics.',
    loadingTitle: 'Dissecting binary structure & evaluating heuristics…',
    loadingSub: 'Computing cryptographic hashes, section entropy, import tables, and threat signatures.',
    dropOverlay: 'Drop executable to start static inspection',

    // Scanner Sub-tabs
    subTabOverview: 'Findings & Hashes',
    subTabStructure: 'PE Structure & Sections',
    subTabImports: 'Imports & Exports',
    subTabStrings: 'Strings & IOCs',
    subTabRules: 'YARA / Sigma & Telemetry',
    subTabAll: 'Full Report View',

    // Active Guard Dashboard
    guardTitle: 'Endpoint Protection & Antivirus Center',
    guardSubtitle: 'Reactive monitoring of high-risk folders, on-demand scans with Start/Stop control, and Anti-Ransomware Canary traps.',
    guardBannerActiveTitle: 'Real-Time Active Protection Running',
    guardBannerActiveDesc: 'The engine is actively watching critical drop folders (Downloads, Desktop, Temp) for newly created binaries and scripts.',
    guardBannerIdleTitle: 'Real-Time Monitoring Paused',
    guardBannerIdleDesc: 'Click "Start Protection" to continuously watch high-risk folders or run a Quick Scan below.',
    guardBannerAlertTitle: 'Critical Alert: Canary Honeypot Tampering Detected',
    guardBannerAlertDesc: 'An Anti-Ransomware decoy file was modified or deleted. Inspect the security alerts and active processes immediately.',
    btnStartShield: 'Start Protection',
    btnStopShield: 'Stop Protection',
    btnStartQuickScan: 'Start Quick Scan',
    btnStartCustomScan: 'Select Folder & Scan',
    btnStopScan: 'Stop Scan',
    scanCenterTitle: 'Antivirus Scan Center',
    scanQuickTitle: 'Quick Scan (High-Risk Drop Zones)',
    scanQuickDesc: 'Scans executables and scripts across Downloads, Desktop, and user Temp directories.',
    scanCustomTitle: 'Custom Directory Scan',
    scanCustomDesc: 'Choose any folder, external drive, or directory for recursive threat inspection.',
    scanBinaryTitle: 'Deep Binary Forensic Analysis (.exe / .dll)',
    scanBinaryDesc: 'Dissects PE headers, computes section entropy, extracts strings/IOCs, and validates YARA/Sigma rules.',
    scanRunningTitle: 'Antivirus Scan in Progress…',
    scanCompletedTitle: 'Last Scan Completed',
    scanAbortedTitle: 'Scan Stopped by User',
    scanCurrentFileLabel: 'Inspecting file:',
    guardRealtimeToggle: 'Continuous Folder Watch (Downloads, Desktop, Temp)',
    guardAutoBlockToggle: 'Transactional AES-256-GCM Vault with Mandatory Manual Confirmation',
    guardCanaryToggle: 'Anti-Ransomware Decoy Trap (Canary Honeypot)',
    metricShield: 'Engine Status',
    metricShieldOn: 'ACTIVE (REAL-TIME)',
    metricShieldOff: 'ON-DEMAND',
    metricCanary: 'Anti-Ransomware Honeypot',
    metricCanaryIntact: 'INTACT (WATCHING)',
    metricCanaryTampered: 'TAMPERED (CRITICAL ALERT)',
    metricCanaryOff: 'DISABLED',
    metricScanned: 'Files Inspected',
    metricBlocked: 'Threats Isolated',
    watchedFoldersTitle: 'Monitored Directories',
    canaryFilesTitle: 'Decoy Files (Canary Honeypots)',
    alertsTitle: 'Security Alerts & Event Log',
    btnClearAlerts: 'Clear Log',
    noAlerts: 'No suspicious events recorded in monitored zones.',
    processesTitle: 'Suspicious Running Processes (Outside Trusted System Paths)',
    btnRefreshProcesses: 'Refresh List',
    btnKillProcess: 'Terminate Process',
    btnKillAndQuarantine: 'Terminate + Quarantine',
    noSuspiciousProcesses: 'No suspicious processes detected outside standard Windows system directories.',
    colPid: 'PID',
    colProcess: 'Process',
    colPath: 'Path / Command Line',
    colRisk: 'Classification / Reason',
    colAction: 'Actions',

    // Quarantine Tab
    quarantineTitle: 'Encrypted Quarantine Vault',
    quarantineSubtitle: 'Isolated files protected with AES-256-GCM authenticated encryption, anti-symlink validation, and SHA-256 integrity checks.',
    noQuarantine: 'No isolated files in the quarantine vault.',
    btnRestore: 'Restore File',
    btnDeletePerm: 'Delete Permanently',
    btnQuarantineCurrent: 'Isolate in Quarantine',
    colDate: 'Timestamp',
    colFile: 'File / Original Path',
    colCategory: 'Classification',
    colScore: 'Risk',

    // Scanner Results
    sampleAnalyzed: 'PE FORENSIC INSPECTION REPORT',
    btnNewAnalysis: 'Analyze Another File',
    btnImportTelemetry: 'Import Telemetry',
    btnPrintPdf: 'Export PDF / Print',
    sessionHistory: 'Recent Session Files',
    riskScoreLabel: 'Risk Score',
    confidenceLabel: 'Analytical Confidence',
    decisionLabel: 'Operational Recommendation',
    riskLow: 'Low Risk',
    riskMedium: 'Moderate Risk',
    riskHigh: 'High Risk',
    riskCritical: 'Critical Risk',

    // Rule Test Lab
    ruleLabTitle: 'Detection Rule Test Lab (YARA & Sigma)',
    ruleLabYaraOk: 'YARA syntax validated and self-tested against current sample',
    ruleLabSigmaOk: 'Sigma YAML schema and deterministic UUID v4 validated',

    // Behavioral Correlation
    correlationTitle: 'Multi-Stage Behavioral Correlation (Sysmon / Telemetry)',
    correlationEmpty: 'No multi-stage behavioral chains correlated in imported events.',

    // Threat Summary Cards
    cardRansomware: 'Ransomware Indicators',
    cardInfostealer: 'Infostealer / Credentials & Cookies',
    cardInjection: 'Process Injection & Evasion',
    statusDetected: 'DETECTED',
    statusClean: 'Not detected',

    // Metrics
    labelArch: 'Architecture',
    labelSubsystem: 'Subsystem',
    labelEntryPoint: 'Entry Point',
    labelImageBase: 'Image Base',
    labelTimestamp: 'Compile Timestamp',
    labelSigned: 'WIN_CERTIFICATE Table',
    labelTls: 'TLS Callbacks',
    labelSize: 'File Size',
    yes: 'Yes',
    no: 'Absent',
    yesWarn: 'Present (Caution)',
    noClean: 'Absent',
    certUnverified: 'Present (Unverified)',

    // Hashes & Comparator
    hashesTitle: 'Cryptographic Signatures & Hash Comparator',
    hashComparePlaceholder: 'Enter an expected SHA-256, SHA-1, or MD5 hash for instant verification…',
    hashMatch: 'Exact cryptographic match confirmed with the provided hash.',
    hashMismatch: 'Hash mismatch: file does not match the provided value.',

    // Findings
    findingsTitle: 'Static Evidence & Heuristics Matrix',
    filterAll: 'All',
    noFindingsInCat: 'No findings recorded for the selected filters.',

    // Sections & Mitigations
    sectionsTitle: 'PE Section Table',
    colSecName: 'Section',
    colSecRva: 'RVA',
    colSecVirtual: 'Virtual Size',
    colSecRaw: 'Raw Size',
    colSecEntropy: 'Entropy (0–8)',
    colSecFlags: 'Permissions',
    mitigationsTitle: 'Exploit Mitigations & Binary Hardening',

    // Imports & Exports
    importsTitle: 'Import Address Table (IAT)',
    exportsTitle: 'Export Address Table (EAT)',
    functionsCount: 'APIs',
    btnFunctions: 'Functions',
    btnDlls: 'Libraries (DLLs)',
    searchFunctionsPlaceholder: 'Search API or DLL name (e.g. Crypt, VirtualAlloc, WinHttp)…',
    noImports: 'No static imports identified.',
    noExports: 'No functions exported by this binary.',
    showingTop: 'Showing top',
    ofTotal: 'of',

    // Indicators & Strings
    indicatorsTitle: 'Extracted Indicators (IOCs)',
    stringsTitle: 'String Inspector (ASCII & UTF-16LE)',
    searchStringsPlaceholder: 'Search strings (e.g. Cookie, Login Data, vssadmin, .onion, http)…',
    noStrings: 'No strings matching current filter.',
    telemetryTitle: 'External Telemetry Timeline (Sysmon / Sandbox)',
    telemetryEmpty: 'Import a JSON file containing Sysmon events (IDs 1, 3, 8, 10, 11, 12–14, 22) for behavioral correlation.',
    extraMetaTitle: 'Extended Metadata (.NET CLR, Delay-Imports, UAC Manifest & Overlay)',
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

