export type Language = 'pt' | 'en'

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'

export type EvidenceType = 'capability' | 'indicator' | 'context' | 'observed'

export type ResponseDecision = 'observe' | 'alert' | 'block'

export type FindingCategory =
  | 'ransomware'
  | 'infostealer'
  | 'packer'
  | 'injection'
  | 'persistence'
  | 'evasion'
  | 'privilege-escalation'
  | 'network'
  | 'general'

export type Finding = {
  id?: string
  severity: Severity
  category: FindingCategory
  evidenceType: EvidenceType
  title: string
  evidence: string
}

export type ImportedFunction = {
  dll: string
  name?: string
  ordinal?: number
}

export type ExportedFunction = {
  name?: string
  ordinal: number
  rva: string
}

export type PeSection = {
  name: string
  virtualAddress: string
  virtualSize: number
  rawSize: number
  characteristics: string
  entropy: number
  flags: string[]
  sha256?: string
  isAnomalousSize?: boolean
}

export type TelemetryEvent = {
  timestamp: string
  source: string
  eventType: string
  eventId?: number
  process?: string
  parentProcess?: string
  pid?: number
  detail: string
  confidence: 'observed' | 'inferred'
}

export type CorrelatedChain = {
  id: string
  severity: Severity
  category: FindingCategory
  title: string
  process: string
  steps: Array<{ timestamp: string; stage: string; evidence: string }>
  justification: string
}

export type RuleValidationResult = {
  yaraValid: boolean
  sigmaValid: boolean
  matchesCurrentSample: boolean
  matchedStringsCount: number
  warnings: string[]
}

export type PeAnalysis = {
  fileName: string
  filePath?: string
  fileSize: number
  sha256: string
  md5: string
  sha1: string
  impHash: string
  architecture: string
  subsystem: string
  timestamp: string
  entryPoint: string
  imageBase: string
  pdbPath?: string
  richHeaderHash?: string
  overlay?: { offset: number; size: number }
  sections: PeSection[]
  imports: string[]                     // DLL names only (backward compat)
  importedFunctions: ImportedFunction[] // full per-function list
  exports: ExportedFunction[]
  strings: string[]                     // ASCII strings
  unicodeStrings: string[]              // UTF-16LE strings
  indicators: { urls: string[]; domains: string[]; paths: string[]; ips: string[] }
  findings: Finding[]
  riskScore: number
  confidenceScore: number
  recommendedDecision: ResponseDecision
  decisionRationale: string
  hasTlsCallbacks: boolean
  isAuthenticodeSigned: boolean
  authenticodeStatus: 'unsigned' | 'present_unverified'
  isDotNet: boolean
  hasDelayImports: boolean
  apiSetImports: string[]
  embeddedManifest?: { executionLevel?: string }
  dllCharacteristics: string[]
}

// ── Real-Time Endpoint Guard Types ────────────────────────────────────────────

export type GuardAlert = {
  id: string
  timestamp: string
  severity: Severity
  category: FindingCategory
  title: string
  filePath: string
  fileName: string
  sha256?: string
  riskScore: number
  actionTaken: 'quarantined' | 'blocked_process' | 'alerted' | 'canary_triggered'
  details: string[]
}

export type QuarantineItem = {
  id: string
  quarantinedAt: string
  originalPath: string
  fileName: string
  fileSize: number
  sha256: string
  riskScore: number
  category: FindingCategory
  reasons: string[]
  encryptedVault?: boolean
}

export type SuspiciousProcess = {
  pid: number
  name: string
  executablePath: string
  commandLine: string
  creationDate?: string
  riskLevel: 'high' | 'medium' | 'low'
  reason: string
}

export type GuardStatus = {
  enabled: boolean
  autoQuarantine: boolean
  canaryEnabled: boolean
  canaryStatus: 'intact' | 'tampered' | 'disabled'
  watchedFolders: string[]
  canaryFiles: string[]
  filesScannedCount: number
  threatsBlockedCount: number
  lastScanAt?: string
  alerts: GuardAlert[]
  quarantine: QuarantineItem[]
}

export interface SentinelGuardAPI {
  getStatus: () => Promise<GuardStatus>
  setConfig: (config: { enabled?: boolean; autoQuarantine?: boolean; canaryEnabled?: boolean }) => Promise<GuardStatus>
  scanDirectory: () => Promise<{ scanned: number; threats: number }>
  quarantineFile: (filePath: string, reason?: string) => Promise<{ ok: boolean; error?: string }>
  restoreQuarantine: (id: string) => Promise<{ ok: boolean; error?: string }>
  deleteQuarantine: (id: string) => Promise<{ ok: boolean; error?: string }>
  listProcesses: () => Promise<SuspiciousProcess[]>
  killProcess: (pid: number, quarantineExe?: boolean) => Promise<{ ok: boolean; error?: string }>
  clearAlerts: () => Promise<GuardStatus>
  onStatusUpdate: (callback: (status: GuardStatus) => void) => () => void
}

declare global {
  interface Window {
    sentinelGuard?: SentinelGuardAPI
  }
}
