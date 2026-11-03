import { app, BrowserWindow, dialog, ipcMain, Notification, safeStorage, screen, shell } from 'electron'
import path from 'node:path'
import fs from 'node:fs'
import os from 'node:os'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

// ── Types ─────────────────────────────────────────────────────────────────────
type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'
type FindingCategory =
  | 'ransomware'
  | 'infostealer'
  | 'packer'
  | 'injection'
  | 'persistence'
  | 'evasion'
  | 'privilege-escalation'
  | 'network'
  | 'general'

interface GuardAlert {
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

interface QuarantineItem {
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
  ivHex?: string
  authTagHex?: string
}

interface SuspiciousProcess {
  pid: number
  name: string
  executablePath: string
  commandLine: string
  creationDate?: string
  riskLevel: 'high' | 'medium' | 'low'
  reason: string
}

interface ScanProgress {
  running: boolean
  mode: 'quick' | 'custom' | 'idle'
  scanned: number
  total: number
  threats: number
  currentFile: string
  startedAt?: string
  completedAt?: string
  aborted?: boolean
}

interface GuardStatus {
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
  scanProgress?: ScanProgress
}

// ── State (Opt-In Active Monitoring & Manual Quarantine by default) ───────────
let mainWindow: BrowserWindow | null = null
let scanAbortRequested = false
const activeWatchers: fs.FSWatcher[] = []
const canaryWatchers: fs.FSWatcher[] = []
const debounceTimers = new Map<string, NodeJS.Timeout>()

const CANARY_TOKEN =
  'SENTINEL-PE-CANARY-DECOY-DO-NOT-MODIFY-OR-ENCRYPT-9F8A7B6C5D4E3F2A1B0C'

const state: GuardStatus = {
  enabled: false,          // Opt-in by default
  autoQuarantine: false,   // Quarantine is manual with explicit confirmation
  canaryEnabled: false,    // Opt-in by default
  canaryStatus: 'disabled',
  watchedFolders: [],
  canaryFiles: [],
  filesScannedCount: 0,
  threatsBlockedCount: 0,
  alerts: [],
  quarantine: [],
  scanProgress: {
    running: false,
    mode: 'idle',
    scanned: 0,
    total: 0,
    threats: 0,
    currentFile: '',
  },
}

// ── Trusted IPC Sender Verification ───────────────────────────────────────────
const getExpectedUiFilePath = () =>
  path.normalize(path.join(__dirname, '../dist/index.html')).toLowerCase()

function isTrustedLocalSender(event: Electron.IpcMainInvokeEvent): boolean {
  if (!mainWindow || mainWindow.isDestroyed()) return false
  if (event.sender.id !== mainWindow.webContents.id) return false
  if (!event.senderFrame || event.senderFrame !== mainWindow.webContents.mainFrame) return false

  const frameUrl = event.senderFrame.url || ''
  const devUrl = process.env.VITE_DEV_SERVER_URL
  if (devUrl) {
    try {
      return new URL(frameUrl).origin === new URL(devUrl).origin
    } catch {
      return false
    }
  }

  if (!frameUrl.startsWith('file://')) return false
  try {
    const actualFile = path.normalize(fileURLToPath(frameUrl)).toLowerCase()
    return actualFile === getExpectedUiFilePath()
  } catch {
    return false
  }
}

function assertTrustedSender(event: Electron.IpcMainInvokeEvent): void {
  if (!isTrustedLocalSender(event)) {
    throw new Error('Unauthorized IPC caller: request did not originate from the trusted local UI.')
  }
}

// ── Paths, Audit Trail & AES-256-GCM Vault Key ────────────────────────────────
const getQuarantineDir = () => path.join(app.getPath('userData'), 'quarantine')
const getManifestPath = () => path.join(getQuarantineDir(), 'manifest.json')
const getAuditLogPath = () => path.join(getQuarantineDir(), 'audit.jsonl')
const getVaultKeyPath = () => path.join(getQuarantineDir(), 'vault.key')

function getOrCreateVaultKey(): Buffer {
  const dir = getQuarantineDir()
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
  const keyPath = getVaultKeyPath()
  if (fs.existsSync(keyPath)) {
    const raw = fs.readFileSync(keyPath)
    if (raw.length === 32) return raw
    try {
      if (safeStorage.isEncryptionAvailable()) {
        const hexKey = safeStorage.decryptString(raw)
        if (/^[0-9a-f]{64}$/i.test(hexKey)) {
          return Buffer.from(hexKey, 'hex')
        }
      }
    } catch {
      // Fall through to regenerate if corrupted
    }
  }
  const newKey = crypto.randomBytes(32)
  try {
    if (safeStorage.isEncryptionAvailable()) {
      const dpapiBlob = safeStorage.encryptString(newKey.toString('hex'))
      fs.writeFileSync(keyPath, dpapiBlob, { mode: 0o600 })
      return newKey
    }
  } catch {
    // Fallback if DPAPI unavailable in headless environment
  }
  fs.writeFileSync(keyPath, newKey, { mode: 0o600 })
  return newKey
}

function appendAuditLog(entry: Record<string, unknown>) {
  try {
    const dir = getQuarantineDir()
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    const line = JSON.stringify({ timestampUtc: new Date().toISOString(), ...entry }) + '\n'
    fs.appendFileSync(getAuditLogPath(), line, 'utf8')
  } catch {
    // Ignore audit write error
  }
}

function loadQuarantineManifest() {
  try {
    const dir = getQuarantineDir()
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    const manifest = getManifestPath()
    if (fs.existsSync(manifest)) {
      const data = JSON.parse(fs.readFileSync(manifest, 'utf8')) as {
        quarantine?: QuarantineItem[]
        alerts?: GuardAlert[]
        filesScannedCount?: number
        threatsBlockedCount?: number
      }
      if (Array.isArray(data.quarantine)) state.quarantine = data.quarantine
      if (Array.isArray(data.alerts)) state.alerts = data.alerts.slice(0, 100)
      if (typeof data.filesScannedCount === 'number') state.filesScannedCount = data.filesScannedCount
      if (typeof data.threatsBlockedCount === 'number') state.threatsBlockedCount = data.threatsBlockedCount
    }
  } catch {
    // Ignore corrupt manifest
  }
}

function saveQuarantineManifest() {
  try {
    const dir = getQuarantineDir()
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    const tmpPath = `${getManifestPath()}.tmp`
    fs.writeFileSync(
      tmpPath,
      JSON.stringify(
        {
          quarantine: state.quarantine,
          alerts: state.alerts.slice(0, 100),
          filesScannedCount: state.filesScannedCount,
          threatsBlockedCount: state.threatsBlockedCount,
        },
        null,
        2,
      ),
      'utf8',
    )
    fs.renameSync(tmpPath, getManifestPath())
  } catch {
    // Ignore write errors
  }
}

function broadcastStatus() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('guard:status-updated', state)
  }
}

function notifyUser(title: string, body: string) {
  try {
    if (Notification.isSupported()) {
      new Notification({ title, body }).show()
    }
  } catch {
    // Ignore notification errors
  }
}

// ── Fast Binary & Script Threat Scanner ───────────────────────────────────────
const MONITORED_EXTENSIONS = new Set([
  '.exe', '.dll', '.scr', '.com', '.sys', '.drv', '.ocx', '.cpl', '.bat', '.cmd', '.ps1', '.vbs',
])

function calculateEntropy(buf: Buffer): number {
  if (buf.length === 0) return 0
  const counts = new Uint32Array(256)
  for (let i = 0; i < buf.length; i++) counts[buf[i]]++
  let ent = 0
  for (let i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      const p = counts[i] / buf.length
      ent -= p * Math.log2(p)
    }
  }
  return ent
}

function extractPrintableText(buf: Buffer): string {
  const ascii = buf.toString('latin1')
  const utf16 = buf.toString('utf16le')
  return `${ascii}\n${utf16}`
}

function inspectFileSync(filePath: string): {
  isThreat: boolean
  riskScore: number
  severity: Severity
  category: FindingCategory
  sha256: string
  fileSize: number
  reasons: string[]
} | null {
  try {
    const lstat = fs.lstatSync(filePath)
    if (lstat.isSymbolicLink() || !lstat.isFile() || lstat.size === 0 || lstat.size > 128 * 1024 * 1024) {
      return null
    }

    const fd = fs.openSync(filePath, 'r')
    const readSize = Math.min(lstat.size, 16 * 1024 * 1024)
    const buf = Buffer.alloc(readSize)
    fs.readSync(fd, buf, 0, readSize, 0)
    fs.closeSync(fd)

    const isMZ = buf.length >= 64 && buf.readUInt16LE(0) === 0x5a4d
    const ext = path.extname(filePath).toLowerCase()
    if (!isMZ && !MONITORED_EXTENSIONS.has(ext)) return null

    state.filesScannedCount += 1
    state.lastScanAt = new Date().toISOString()

    const hashSource = lstat.size === readSize ? buf : fs.readFileSync(filePath)
    const fullHash = crypto.createHash('sha256').update(hashSource).digest('hex')
    const text = extractPrintableText(buf)
    const reasons: string[] = []
    let score = 0
    let primaryCategory: FindingCategory = 'general'

    if (/vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+catalog/i.test(text)) {
      score += 55
      primaryCategory = 'ransomware'
      reasons.push('Shadow Copy Deletion Command (vssadmin/wmic/wbadmin)')
    }
    if (/bcdedit.*recoveryenabled\s+no|bcdedit.*bootstatuspolicy|reagentc.*\/disable/i.test(text)) {
      score += 45
      primaryCategory = 'ransomware'
      reasons.push('Boot Recovery Sabotage (bcdedit/reagentc)')
    }
    if (
      (/CryptEncrypt|BCryptEncrypt|NCryptEncrypt/i.test(text) && /FindFirstFile|FindNextFile/i.test(text)) ||
      /your files (have been|are) encrypted|to decrypt your files|send.*bitcoin/i.test(text)
    ) {
      score += 45
      if (primaryCategory === 'general') primaryCategory = 'ransomware'
      reasons.push('Mass File Encryption / Ransom Note Pattern')
    }
    if (/[a-z2-7]{16,56}\.onion/i.test(text)) {
      score += 25
      if (primaryCategory === 'general') primaryCategory = 'ransomware'
      reasons.push('Tor Hidden Service (.onion) C2 Address')
    }

    if (
      /\\User Data\\Default\\Login Data|\\User Data\\Default\\Network\\Cookies|\\User Data\\Local State|cookies\.sqlite|SELECT\s+origin_url,\s*username_value,\s*password_value/i.test(
        text,
      )
    ) {
      score += 55
      if (primaryCategory === 'general') primaryCategory = 'infostealer'
      reasons.push('Browser Session Cookies & Login Data Theft (Chrome/Edge/Brave/Firefox)')
    }
    if (/lsass\.exe.*MiniDump|MiniDumpWriteDump.*lsass|sekurlsa::|reg\s+save\s+hklm\\sam/i.test(text)) {
      score += 55
      if (primaryCategory === 'general') primaryCategory = 'infostealer'
      reasons.push('LSASS / SAM Credential Dumping Detected')
    }
    if (
      /\\discord\\Local Storage\\leveldb|Telegram Desktop\\tdata|nkbihfbeogaeaoehlefnkodbefgpgknn|\\Exodus\\exodus\.wallet/i.test(
        text,
      )
    ) {
      score += 40
      if (primaryCategory === 'general') primaryCategory = 'infostealer'
      reasons.push('Session Token / Crypto Wallet Theft (Discord/Telegram/MetaMask/Exodus)')
    }
    if (/CryptUnprotectData/i.test(text) && (/Login Data|Cookies|Local State|VaultEnumerateItems/i.test(text))) {
      score += 35
      if (primaryCategory === 'general') primaryCategory = 'infostealer'
      reasons.push('Windows DPAPI Master Key Decryption (CryptUnprotectData)')
    }

    if (
      /VirtualAllocEx/i.test(text) &&
      /WriteProcessMemory/i.test(text) &&
      (/CreateRemoteThread|NtCreateThreadEx|QueueUserAPC/i.test(text))
    ) {
      score += 35
      if (primaryCategory === 'general') primaryCategory = 'injection'
      reasons.push('Remote Process Injection Triad (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)')
    }

    if (isMZ) {
      const ent = calculateEntropy(buf)
      if (ent >= 7.6 && lstat.size > 16384) {
        score += 25
        if (primaryCategory === 'general') primaryCategory = 'packer'
        reasons.push(`High Binary Entropy (${ent.toFixed(2)} bits/byte — Packed/Encrypted Payload)`)
      }
    }

    const finalScore = Math.min(100, score)
    const severity: Severity =
      finalScore >= 80 ? 'critical' :
      finalScore >= 50 ? 'high' :
      finalScore >= 25 ? 'medium' :
      finalScore > 0 ? 'low' : 'informational'

    return {
      isThreat: finalScore >= 50,
      riskScore: finalScore,
      severity,
      category: primaryCategory,
      sha256: fullHash,
      fileSize: lstat.size,
      reasons,
    }
  } catch {
    return null
  }
}

// ── 6-Step Transactional, Symlink-Safe & AES-256-GCM Encrypted Quarantine ─────
function isProtectedPath(filePath: string): boolean {
  const norm = path.normalize(filePath).toLowerCase()
  const winDir = (process.env.WINDIR ?? 'C:\\Windows').toLowerCase()
  const progFiles = (process.env.PROGRAMFILES ?? 'C:\\Program Files').toLowerCase()
  const progFiles86 = (process.env['PROGRAMFILES(X86)'] ?? 'C:\\Program Files (x86)').toLowerCase()
  const appDir = path.dirname(process.execPath).toLowerCase()
  const userDataDir = app.getPath('userData').toLowerCase()

  return (
    norm.startsWith(winDir) ||
    norm.startsWith(progFiles) ||
    norm.startsWith(progFiles86) ||
    norm.startsWith(appDir) ||
    norm.startsWith(userDataDir)
  )
}

function quarantineFileReversibleSync(
  filePath: string,
  meta: {
    sha256: string
    fileSize: number
    riskScore: number
    category: FindingCategory
    reasons: string[]
  },
): { item?: QuarantineItem; error?: string } {
  try {
    // Step 1: Identification & Symlink / Reparse Point Rejection
    const resolvedPath = path.resolve(filePath)
    if (!fs.existsSync(resolvedPath)) {
      return { error: 'Arquivo não encontrado no disco / File not found on disk.' }
    }
    const lstat = fs.lstatSync(resolvedPath)
    if (lstat.isSymbolicLink() || !lstat.isFile()) {
      return { error: 'Links simbólicos (symlinks) ou reparse points não podem ser quarentenados.' }
    }
    if (isProtectedPath(resolvedPath)) {
      return { error: 'Diretório protegido do sistema ou da aplicação não pode ser quarentenado.' }
    }

    // Step 2: TOCTOU Verification of original content
    const originalBytes = fs.readFileSync(resolvedPath)
    const currentSha256 = crypto.createHash('sha256').update(originalBytes).digest('hex')
    if (meta.sha256 && meta.sha256.length === 64 && currentSha256 !== meta.sha256) {
      return { error: 'O conteúdo do arquivo mudou desde a análise inicial (TOCTOU detectado).' }
    }

    // Step 3: AES-256-GCM Encrypted & Authenticated Vault Storage
    const qDir = getQuarantineDir()
    if (!fs.existsSync(qDir)) fs.mkdirSync(qDir, { recursive: true })
    const key = getOrCreateVaultKey()
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
    const encrypted = Buffer.concat([cipher.update(originalBytes), cipher.final()])
    const authTag = cipher.getAuthTag()

    const id = crypto.randomUUID()
    const destPath = path.join(qDir, `${id}.quarantine`)
    fs.writeFileSync(destPath, encrypted, { mode: 0o600 })

    // Step 4: Integrity Verification before removing original file
    const verifyCipher = fs.readFileSync(destPath)
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(authTag)
    const decryptedCheck = Buffer.concat([decipher.update(verifyCipher), decipher.final()])
    const verifiedHash = crypto.createHash('sha256').update(decryptedCheck).digest('hex')
    if (verifiedHash !== currentSha256) {
      fs.unlinkSync(destPath)
      return { error: 'Falha na verificação criptográfica AES-256-GCM do cofre.' }
    }

    // Remove original only after verified encrypted vault write
    fs.unlinkSync(resolvedPath)

    // Step 5: Transactional Manifest & Audit Trail
    const item: QuarantineItem = {
      id,
      quarantinedAt: new Date().toISOString(),
      originalPath: resolvedPath,
      fileName: path.basename(resolvedPath),
      fileSize: originalBytes.length,
      sha256: currentSha256,
      riskScore: meta.riskScore,
      category: meta.category,
      reasons: meta.reasons,
      encryptedVault: true,
      ivHex: iv.toString('hex'),
      authTagHex: authTag.toString('hex'),
    }

    state.quarantine.unshift(item)
    state.threatsBlockedCount += 1
    saveQuarantineManifest()
    appendAuditLog({
      action: 'QUARANTINE_FILE',
      quarantineId: id,
      originalPath: resolvedPath,
      sha256: currentSha256,
      riskScore: meta.riskScore,
    })
    return { item }
  } catch (err) {
    return { error: err instanceof Error ? err.message : 'Erro ao quarentenar arquivo.' }
  }
}

// ── Handle File Event in Monitored Folders (Reactive Alert, Manual Action) ────
function handleMonitoredFile(filePath: string) {
  if (!state.enabled) return
  const ext = path.extname(filePath).toLowerCase()
  if (!MONITORED_EXTENSIONS.has(ext)) return

  const res = inspectFileSync(filePath)
  if (!res) {
    broadcastStatus()
    return
  }

  if (res.isThreat) {
    const alert: GuardAlert = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      severity: res.severity,
      category: res.category,
      title: `Arquivo Suspeito Detectado (${res.category.toUpperCase()})`,
      filePath: path.resolve(filePath),
      fileName: path.basename(filePath),
      sha256: res.sha256,
      riskScore: res.riskScore,
      actionTaken: 'alerted',
      details: res.reasons,
    }

    state.alerts.unshift(alert)
    saveQuarantineManifest()
    notifyUser(
      '⚠️ Sentinel PE — Arquivo Suspeito Detectado',
      `${alert.fileName} (Score: ${res.riskScore}/100). Abra o Sentinel PE para revisar e quarentenar.`,
    )
  }

  broadcastStatus()
}

// ── Canary Honeypot Setup (Opt-In) ────────────────────────────────────────────
function setupCanaryHoneypots() {
  for (const w of canaryWatchers) {
    try { w.close() } catch { /* ignore */ }
  }
  canaryWatchers.length = 0
  state.canaryFiles = []

  if (!state.canaryEnabled) {
    state.canaryStatus = 'disabled'
    broadcastStatus()
    return
  }

  const canaryDir = path.join(app.getPath('userData'), 'CanaryTrap')
  try {
    if (!fs.existsSync(canaryDir)) fs.mkdirSync(canaryDir, { recursive: true })
    const files = [
      path.join(canaryDir, '!000_Sentinel_Canary_Passwords_DoNotTouch.txt'),
      path.join(canaryDir, '!000_Sentinel_Canary_Financial_Backup.csv'),
    ]

    for (const cFile of files) {
      fs.writeFileSync(cFile, CANARY_TOKEN, 'utf8')
      state.canaryFiles.push(cFile)

      const watcher = fs.watch(cFile, () => {
        try {
          const exists = fs.existsSync(cFile)
          const content = exists ? fs.readFileSync(cFile, 'utf8') : ''
          if (!exists || content !== CANARY_TOKEN) {
            state.canaryStatus = 'tampered'
            const alert: GuardAlert = {
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              severity: 'critical',
              category: 'ransomware',
              title: '🚨 ARMADILHA CANARY VIOLADA — Possível Ransomware Ativo!',
              filePath: cFile,
              fileName: path.basename(cFile),
              riskScore: 100,
              actionTaken: 'canary_triggered',
              details: [
                !exists
                  ? 'Arquivo-isca Canary foi excluído por um processo externo.'
                  : 'Conteúdo do arquivo-isca Canary foi criptografado ou modificado.',
              ],
            }
            state.alerts.unshift(alert)
            saveQuarantineManifest()
            appendAuditLog({ action: 'CANARY_TAMPERED', filePath: cFile })
            notifyUser(
              '🚨 ALERTA CRÍTICO DE RANSOMWARE!',
              `Armadilha Canary violada (${path.basename(cFile)}). Verifique processos suspeitos imediatamente!`,
            )
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.show()
              mainWindow.focus()
            }
            broadcastStatus()
          }
        } catch {
          // Ignore transient lock
        }
      })
      canaryWatchers.push(watcher)
    }

    state.canaryStatus = 'intact'
  } catch {
    state.canaryStatus = 'disabled'
  }
  broadcastStatus()
}

// ── Folder Watchers Setup (Opt-In Reactive Monitoring) ────────────────────────
function setupFolderWatchers() {
  for (const w of activeWatchers) {
    try { w.close() } catch { /* ignore */ }
  }
  activeWatchers.length = 0
  state.watchedFolders = []

  if (!state.enabled) {
    broadcastStatus()
    return
  }

  const candidates = [
    app.getPath('downloads'),
    app.getPath('desktop'),
    os.tmpdir(),
  ]

  const uniqueDirs = [...new Set(candidates)].filter(d => {
    try { return fs.existsSync(d) && fs.statSync(d).isDirectory() } catch { return false }
  })

  for (const dir of uniqueDirs) {
    try {
      const watcher = fs.watch(dir, (_eventType, filename) => {
        if (!filename) return
        const fullPath = path.join(dir, filename)
        const ext = path.extname(fullPath).toLowerCase()
        if (!MONITORED_EXTENSIONS.has(ext)) return

        const prev = debounceTimers.get(fullPath)
        if (prev) clearTimeout(prev)
        debounceTimers.set(
          fullPath,
          setTimeout(() => {
            debounceTimers.delete(fullPath)
            handleMonitoredFile(fullPath)
          }, 450),
        )
      })
      activeWatchers.push(watcher)
      state.watchedFolders.push(dir)
    } catch {
      // Skip inaccessible directory
    }
  }

  broadcastStatus()
}

// ── Suspicious Process Scanner (with CreationDate Identity) ───────────────────
async function scanRunningProcesses(): Promise<SuspiciousProcess[]> {
  if (process.platform !== 'win32') return []
  try {
    const psCommand =
      'Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine, CreationDate | ConvertTo-Json -Compress'
    const { stdout } = await execFileAsync('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      psCommand,
    ], { timeout: 8000, maxBuffer: 10 * 1024 * 1024 })

    if (!stdout.trim()) return []
    const parsed = JSON.parse(stdout)
    const list: Array<{
      ProcessId?: number
      Name?: string
      ExecutablePath?: string | null
      CommandLine?: string | null
      CreationDate?: string | null
    }> = Array.isArray(parsed) ? parsed : [parsed]

    const suspicious: SuspiciousProcess[] = []
    const myPid = process.pid

    for (const proc of list) {
      const pid = proc.ProcessId ?? 0
      if (!pid || pid === myPid || pid <= 4) continue
      const name = proc.Name ?? 'unknown'
      const exePath = proc.ExecutablePath ?? ''
      const cmd = proc.CommandLine ?? ''
      const creationDate = proc.CreationDate ? String(proc.CreationDate) : undefined
      const lowerPath = exePath.toLowerCase()
      const lowerCmd = cmd.toLowerCase()

      if (lowerPath.includes('sentinel pe') || lowerPath.includes('electron.exe')) continue

      if (
        /vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|wbadmin.*delete|bcdedit.*recoveryenabled\s+no/i.test(cmd)
      ) {
        suspicious.push({
          pid,
          name,
          executablePath: exePath || name,
          commandLine: cmd,
          creationDate,
          riskLevel: 'high',
          reason: 'Ransomware Shadow Copy / Boot Recovery Sabotage Command',
        })
        continue
      }

      if (/sekurlsa|lsass.*minidump|reg\s+save\s+hklm\\sam|cryptunprotectdata/i.test(cmd)) {
        suspicious.push({
          pid,
          name,
          executablePath: exePath || name,
          commandLine: cmd,
          creationDate,
          riskLevel: 'high',
          reason: 'Credential / Session Dumping Command Line',
        })
        continue
      }

      if (/powershell.*(-enc|-encodedcommand|frombase64string|-w\s+hidden|-windowstyle\s+hidden)/i.test(cmd)) {
        suspicious.push({
          pid,
          name,
          executablePath: exePath || name,
          commandLine: cmd,
          creationDate,
          riskLevel: 'high',
          reason: 'Hidden / Obfuscated PowerShell Execution',
        })
        continue
      }

      if (
        lowerPath &&
        (lowerPath.includes('\\appdata\\local\\temp\\') ||
          lowerPath.includes('\\downloads\\') ||
          lowerPath.includes('\\users\\public\\'))
      ) {
        suspicious.push({
          pid,
          name,
          executablePath: exePath,
          commandLine: cmd || exePath,
          creationDate,
          riskLevel: 'medium',
          reason: 'Executing from unverified user drop folder (Temp / Downloads / Public)',
        })
      } else if (lowerCmd.includes('\\appdata\\local\\temp\\') && /\.(exe|scr|bat|vbs|ps1)/i.test(lowerCmd)) {
        suspicious.push({
          pid,
          name,
          executablePath: exePath || name,
          commandLine: cmd,
          creationDate,
          riskLevel: 'medium',
          reason: 'Process launched with payload in Temp directory',
        })
      }
    }

    return suspicious
  } catch {
    return []
  }
}

// ── IPC Handlers (Restricted to Trusted Local UI + Explicit Confirmations) ────
function registerIpcHandlers() {
  ipcMain.handle('guard:get-status', (event) => {
    assertTrustedSender(event)
    return state
  })

  ipcMain.handle(
    'guard:set-config',
    (event, config: { enabled?: boolean; autoQuarantine?: boolean; canaryEnabled?: boolean }) => {
      assertTrustedSender(event)
      if (typeof config.enabled === 'boolean' && config.enabled !== state.enabled) {
        state.enabled = config.enabled
        setupFolderWatchers()
      }
      state.autoQuarantine = false
      if (typeof config.canaryEnabled === 'boolean' && config.canaryEnabled !== state.canaryEnabled) {
        state.canaryEnabled = config.canaryEnabled
        setupCanaryHoneypots()
      }
      broadcastStatus()
      return state
    },
  )

  ipcMain.handle('guard:clear-alerts', (event) => {
    assertTrustedSender(event)
    state.alerts = []
    if (state.canaryEnabled && state.canaryStatus === 'tampered') {
      setupCanaryHoneypots()
    }
    saveQuarantineManifest()
    broadcastStatus()
    return state
  })

  const runAsyncFolderScan = async (
    rootDirs: string[],
    mode: 'quick' | 'custom',
  ): Promise<{ scanned: number; threats: number; aborted?: boolean }> => {
    if (state.scanProgress?.running) {
      return { scanned: state.scanProgress.scanned, threats: state.scanProgress.threats }
    }

    scanAbortRequested = false
    const candidates: string[] = []

    const collectFiles = (dir: string, depth = 0) => {
      if (depth > 3 || scanAbortRequested) return
      let entries: fs.Dirent[] = []
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true })
      } catch {
        return
      }

      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue
        const fullPath = path.join(dir, entry.name)
        if (entry.isDirectory()) {
          if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'release') continue
          collectFiles(fullPath, depth + 1)
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase()
          if (MONITORED_EXTENSIONS.has(ext)) {
            candidates.push(fullPath)
          }
        }
      }
    }

    for (const d of rootDirs) {
      if (fs.existsSync(d)) collectFiles(d)
    }

    state.scanProgress = {
      running: true,
      mode,
      scanned: 0,
      total: candidates.length,
      threats: 0,
      currentFile: candidates[0] ?? (rootDirs[0] || ''),
      startedAt: new Date().toISOString(),
      aborted: false,
    }
    broadcastStatus()

    let scanned = 0
    let threats = 0

    for (const fullPath of candidates) {
      if (scanAbortRequested) {
        state.scanProgress = {
          ...state.scanProgress,
          running: false,
          aborted: true,
          completedAt: new Date().toISOString(),
        }
        saveQuarantineManifest()
        broadcastStatus()
        return { scanned, threats, aborted: true }
      }

      scanned++
      state.scanProgress.scanned = scanned
      state.scanProgress.currentFile = fullPath
      if (scanned % 2 === 1 || scanned === candidates.length) {
        broadcastStatus()
      }

      // Yield to event loop so UI updates and Stop Scan IPC is handled immediately
      await new Promise<void>(resolve => setTimeout(resolve, 12))

      const check = inspectFileSync(fullPath)
      if (check && check.isThreat) {
        threats++
        state.scanProgress.threats = threats
        const alert: GuardAlert = {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          severity: check.severity,
          category: check.category,
          title: `Arquivo Suspeito na Varredura (${check.category.toUpperCase()})`,
          filePath: path.resolve(fullPath),
          fileName: path.basename(fullPath),
          sha256: check.sha256,
          riskScore: check.riskScore,
          actionTaken: 'alerted',
          details: check.reasons,
        }
        state.alerts.unshift(alert)
      }
    }

    state.scanProgress = {
      ...state.scanProgress,
      running: false,
      scanned,
      threats,
      currentFile: '',
      completedAt: new Date().toISOString(),
    }
    saveQuarantineManifest()
    broadcastStatus()
    return { scanned, threats, aborted: false }
  }

  ipcMain.handle('guard:stop-scan', (event) => {
    assertTrustedSender(event)
    scanAbortRequested = true
    return { ok: true }
  })

  ipcMain.handle('guard:quick-scan', async (event) => {
    assertTrustedSender(event)
    const dirs = [...new Set([app.getPath('downloads'), app.getPath('desktop'), os.tmpdir()])]
    return await runAsyncFolderScan(dirs, 'quick')
  })

  ipcMain.handle('guard:scan-directory', async (event) => {
    assertTrustedSender(event)
    if (!mainWindow) return { scanned: 0, threats: 0 }
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openDirectory'],
      title: 'Selecionar pasta para varredura / Select folder to scan',
    })
    if (result.canceled || !result.filePaths[0]) return { scanned: 0, threats: 0 }

    return await runAsyncFolderScan([result.filePaths[0]], 'custom')
  })

  ipcMain.handle('guard:quarantine-file', async (event, filePath: string, reason?: string) => {
    assertTrustedSender(event)
    try {
      if (!mainWindow) return { ok: false, error: 'Main window unavailable.' }
      if (!filePath || typeof filePath !== 'string' || !fs.existsSync(filePath)) {
        return { ok: false, error: 'Arquivo não encontrado no disco / File not found on disk.' }
      }
      const resolvedPath = path.resolve(filePath)
      const lstat = fs.lstatSync(resolvedPath)
      if (lstat.isSymbolicLink() || !lstat.isFile()) {
        return { error: 'Links simbólicos (symlinks) não são permitidos.', ok: false }
      }
      if (isProtectedPath(resolvedPath)) {
        return { ok: false, error: 'Caminho do sistema ou da própria aplicação não pode ser quarentenado.' }
      }

      const rawBytes = fs.readFileSync(resolvedPath)
      const initialSha256 = crypto.createHash('sha256').update(rawBytes).digest('hex')

      const confirm = await dialog.showMessageBox(mainWindow, {
        type: 'warning',
        buttons: ['Cancelar / Cancel', 'Confirmar Quarentena / Quarantine File'],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
        title: 'Confirmar Quarentena Manual / Confirm Manual Quarantine',
        message: `Deseja isolar e criptografar "${path.basename(resolvedPath)}" no Cofre de Quarentena?`,
        detail:
          `Caminho original / Original path:\n${resolvedPath}\n` +
          `SHA-256: ${initialSha256}\n\n` +
          `O arquivo será criptografado com AES-256-GCM no cofre isolado do Sentinel PE e registrado na trilha de auditoria. ` +
          `Você poderá restaurá-lo de forma íntegra na aba Quarentena.`,
      })

      if (confirm.response !== 1) {
        return { ok: false, error: 'Operação cancelada pelo usuário / Canceled by user.' }
      }

      const check = inspectFileSync(resolvedPath) ?? {
        sha256: initialSha256,
        fileSize: rawBytes.length,
        riskScore: 80,
        category: 'general' as FindingCategory,
        reasons: [reason ?? 'Manual user quarantine'],
      }
      check.sha256 = initialSha256

      const { item, error } = quarantineFileReversibleSync(resolvedPath, check)
      if (!item) return { ok: false, error: error ?? 'Quarantine failed.' }

      for (const alert of state.alerts) {
        if (path.normalize(alert.filePath).toLowerCase() === path.normalize(resolvedPath).toLowerCase()) {
          alert.actionTaken = 'quarantined'
        }
      }

      state.alerts.unshift({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        severity: 'high',
        category: item.category,
        title: `Arquivo Quarentenado Manualmente (${item.fileName})`,
        filePath: resolvedPath,
        fileName: item.fileName,
        sha256: item.sha256,
        riskScore: item.riskScore,
        actionTaken: 'quarantined',
        details: item.reasons,
      })
      saveQuarantineManifest()
      broadcastStatus()
      return { ok: true }
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : 'Quarantine failed' }
    }
  })

  ipcMain.handle('guard:restore-quarantine', async (event, id: string) => {
    assertTrustedSender(event)
    try {
      if (!mainWindow) return { ok: false, error: 'Main window unavailable.' }
      const idx = state.quarantine.findIndex(q => q.id === id)
      if (idx === -1) return { ok: false, error: 'Item de quarentena não encontrado.' }
      const item = state.quarantine[idx]
      const qFilePath = path.join(getQuarantineDir(), `${item.id}.quarantine`)

      if (!fs.existsSync(qFilePath)) {
        state.quarantine.splice(idx, 1)
        saveQuarantineManifest()
        broadcastStatus()
        return { ok: false, error: 'Arquivo quarentenado não existe mais no cofre.' }
      }

      // Step 6: Validate destination against symlink attacks before restoring
      const destExists = fs.existsSync(item.originalPath)
      if (destExists) {
        const destStat = fs.lstatSync(item.originalPath)
        if (destStat.isSymbolicLink()) {
          return { ok: false, error: 'O destino contém um link simbólico (symlink). Restauração bloqueada.' }
        }
      }

      const confirm = await dialog.showMessageBox(mainWindow, {
        type: 'question',
        buttons: ['Cancelar / Cancel', 'Restaurar Arquivo / Restore File'],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
        title: 'Confirmar Restauração de Quarentena / Confirm Restore',
        message: `Restaurar "${item.fileName}" para o local original?`,
        detail:
          `Destino / Destination:\n${item.originalPath}\n` +
          `SHA-256 esperado: ${item.sha256}\n` +
          (destExists ? '\n⚠️ Atenção: Já existe um arquivo nesse caminho e ele será substituído.' : ''),
      })

      if (confirm.response !== 1) {
        return { ok: false, error: 'Restauração cancelada pelo usuário / Canceled by user.' }
      }

      const targetDir = path.dirname(item.originalPath)
      if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true })

      const vaultBytes = fs.readFileSync(qFilePath)
      let plainBytes: Buffer
      if (item.encryptedVault && item.ivHex && item.authTagHex) {
        const key = getOrCreateVaultKey()
        const decipher = crypto.createDecipheriv(
          'aes-256-gcm',
          key,
          Buffer.from(item.ivHex, 'hex'),
        )
        decipher.setAuthTag(Buffer.from(item.authTagHex, 'hex'))
        plainBytes = Buffer.concat([decipher.update(vaultBytes), decipher.final()])
      } else {
        plainBytes = vaultBytes
      }

      const restoredHash = crypto.createHash('sha256').update(plainBytes).digest('hex')
      if (item.sha256 && item.sha256.length === 64 && restoredHash !== item.sha256) {
        return { ok: false, error: 'Erro de integridade SHA-256 ao descriptografar arquivo do cofre.' }
      }

      fs.writeFileSync(item.originalPath, plainBytes)
      fs.unlinkSync(qFilePath)
      state.quarantine.splice(idx, 1)
      saveQuarantineManifest()
      appendAuditLog({
        action: 'RESTORE_QUARANTINE',
        quarantineId: item.id,
        restoredPath: item.originalPath,
        sha256: restoredHash,
      })
      broadcastStatus()
      return { ok: true }
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : 'Restore failed' }
    }
  })

  ipcMain.handle('guard:delete-quarantine', async (event, id: string) => {
    assertTrustedSender(event)
    try {
      if (!mainWindow) return { ok: false, error: 'Main window unavailable.' }
      const idx = state.quarantine.findIndex(q => q.id === id)
      if (idx === -1) return { ok: false, error: 'Entry not found' }
      const item = state.quarantine[idx]

      const confirm = await dialog.showMessageBox(mainWindow, {
        type: 'warning',
        buttons: ['Cancelar / Cancel', 'Excluir Permanentemente / Delete Permanently'],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
        title: 'Confirmar Exclusão Permanente / Confirm Permanent Deletion',
        message: `Excluir permanentemente "${item.fileName}" do Cofre de Quarentena?`,
        detail:
          `Arquivo: ${item.fileName}\nSHA-256: ${item.sha256}\n\n` +
          `⚠️ Esta ação é irreversível e será registrada na trilha de auditoria.`,
      })

      if (confirm.response !== 1) {
        return { ok: false, error: 'Exclusão cancelada pelo usuário / Canceled by user.' }
      }

      const qFilePath = path.join(getQuarantineDir(), `${item.id}.quarantine`)
      if (fs.existsSync(qFilePath)) fs.unlinkSync(qFilePath)
      state.quarantine.splice(idx, 1)
      saveQuarantineManifest()
      appendAuditLog({
        action: 'DELETE_QUARANTINE_PERMANENT',
        quarantineId: item.id,
        fileName: item.fileName,
        sha256: item.sha256,
      })
      broadcastStatus()
      return { ok: true }
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : 'Delete failed' }
    }
  })

  ipcMain.handle('guard:list-processes', async (event) => {
    assertTrustedSender(event)
    return await scanRunningProcesses()
  })

  ipcMain.handle('guard:kill-process', async (event, pid: number, quarantineExe?: boolean) => {
    assertTrustedSender(event)
    try {
      if (!mainWindow) return { ok: false, error: 'Main window unavailable.' }
      if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 4 || pid === process.pid) {
        return { ok: false, error: 'PID inválido ou protegido.' }
      }

      const initialProcs = await scanRunningProcesses()
      const found = initialProcs.find(p => p.pid === pid)
      if (!found) {
        return { ok: false, error: `Processo PID ${pid} não está mais ativo na lista de processos suspeitos.` }
      }
      const exePath = found.executablePath && fs.existsSync(found.executablePath) ? found.executablePath : ''

      const confirm = await dialog.showMessageBox(mainWindow, {
        type: 'warning',
        buttons: [
          'Cancelar / Cancel',
          quarantineExe
            ? 'Encerrar e Quarentenar / Kill & Quarantine'
            : 'Encerrar Processo / Terminate Process',
        ],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
        title: 'Confirmar Encerramento de Processo / Confirm Process Termination',
        message: `Deseja encerrar o processo ${found.name} (PID ${pid})?`,
        detail:
          `PID: ${pid}\n` +
          `Nome: ${found.name}\n` +
          `Início: ${found.creationDate ?? 'N/A'}\n` +
          `Executável: ${exePath || 'N/A'}\n` +
          `Motivo: ${found.reason}\n` +
          (quarantineExe && exePath
            ? '\nO arquivo executável também será criptografado no Cofre de Quarentena.'
            : ''),
      })

      if (confirm.response !== 1) {
        return { ok: false, error: 'Encerramento cancelado pelo usuário / Canceled by user.' }
      }

      // Re-verify process identity (PID + Name + CreationDate) right before termination to prevent PID reuse race
      const recheckProcs = await scanRunningProcesses()
      const currentTarget = recheckProcs.find(p => p.pid === pid)
      if (
        !currentTarget ||
        currentTarget.name !== found.name ||
        (found.creationDate && currentTarget.creationDate && currentTarget.creationDate !== found.creationDate)
      ) {
        return {
          ok: false,
          error: 'A identidade do processo mudou ou ele já foi encerrado (proteção contra reuso de PID).',
        }
      }

      try {
        process.kill(pid, 'SIGKILL')
      } catch {
        await execFileAsync('taskkill.exe', ['/F', '/PID', String(pid)])
      }

      if (quarantineExe && exePath && fs.existsSync(exePath) && !isProtectedPath(exePath)) {
        const rawBytes = fs.readFileSync(exePath)
        const check = inspectFileSync(exePath) ?? {
          sha256: crypto.createHash('sha256').update(rawBytes).digest('hex'),
          fileSize: rawBytes.length,
          riskScore: 85,
          category: 'general' as FindingCategory,
          reasons: [`Terminated suspicious process PID ${pid} (${found.name})`],
        }
        quarantineFileReversibleSync(exePath, check)
      }

      state.threatsBlockedCount += 1
      state.alerts.unshift({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        severity: 'high',
        category: 'general',
        title: `Processo Suspeito Encerrado (PID ${pid} — ${found.name})`,
        filePath: exePath || `PID:${pid}`,
        fileName: exePath ? path.basename(exePath) : `${found.name} (PID ${pid})`,
        riskScore: 85,
        actionTaken: 'blocked_process',
        details: [
          quarantineExe && exePath
            ? `Processo encerrado e executável movido para a Quarentena (${exePath})`
            : `Processo encerrado manualmente pelo usuário (PID ${pid})`,
        ],
      })
      saveQuarantineManifest()
      appendAuditLog({
        action: 'KILL_PROCESS',
        pid,
        name: found.name,
        executablePath: exePath,
        quarantinedExe: Boolean(quarantineExe && exePath),
      })
      broadcastStatus()
      return { ok: true }
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : 'Failed to terminate process' }
    }
  })
}

// ── Window Lifecycle & Navigation Hardening ───────────────────────────────────
const ALLOWED_EXTERNAL_HOSTS = new Set([
  'www.virustotal.com',
  'virustotal.com',
  'bazaar.abuse.ch',
  'github.com',
])

const createWindow = () => {
  const workArea = screen.getPrimaryDisplay().workAreaSize
  const initialWidth = Math.min(1360, Math.max(960, Math.round(workArea.width * 0.88)))
  const initialHeight = Math.min(860, Math.max(620, Math.round(workArea.height * 0.88)))

  mainWindow = new BrowserWindow({
    width: initialWidth,
    minWidth: 860,
    height: initialHeight,
    minHeight: 560,
    center: true,
    autoHideMenuBar: true,
    backgroundColor: '#0d1117',
    title: 'Sentinel PE — Endpoint Protection & Binary Triage',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  })
  mainWindow.setMenuBarVisibility(false)

  mainWindow.webContents.on('will-navigate', (event) => {
    event.preventDefault()
  })

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    try {
      const parsed = new URL(url)
      if (parsed.protocol === 'https:' && ALLOWED_EXTERNAL_HOSTS.has(parsed.hostname.toLowerCase())) {
        void shell.openExternal(url)
      }
    } catch {
      // Ignore malformed URLs
    }
    return { action: 'deny' }
  })

  if (process.env.VITE_DEV_SERVER_URL) {
    void mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL)
  } else {
    void mainWindow.loadFile(path.join(__dirname, '../dist/index.html'))
  }
}

app.whenReady().then(() => {
  loadQuarantineManifest()
  registerIpcHandlers()
  setupFolderWatchers()
  setupCanaryHoneypots()
  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
