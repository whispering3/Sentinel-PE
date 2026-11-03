import type {
  EvidenceType,
  Finding,
  FindingCategory,
  PeAnalysis,
  ResponseDecision,
  Severity,
} from '../types'

// ── Types ─────────────────────────────────────────────────────────────────────
export type PartialAnalysis = Omit<
  PeAnalysis,
  'findings' | 'riskScore' | 'confidenceScore' | 'recommendedDecision' | 'decisionRationale'
>

type Rule = {
  severity: Severity
  category: FindingCategory
  evidenceType: EvidenceType
  title: string
  /** Return evidence string if rule fires, false otherwise */
  check: (a: PartialAnalysis) => string | false
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const apiSet = (a: PartialAnalysis) =>
  new Set(a.importedFunctions.map(f => f.name?.toLowerCase() ?? ''))

const allStrings = (a: PartialAnalysis) => [...a.strings, ...a.unicodeStrings]

const matchStr = (strings: string[], patterns: RegExp[]) =>
  strings.find(s => patterns.some(p => p.test(s)))

const matchAllStr = (strings: string[], patterns: RegExp[], limit = 4) => {
  const hits: string[] = []
  for (const s of strings) {
    if (patterns.some(p => p.test(s))) {
      hits.push(s.slice(0, 90))
      if (hits.length >= limit) break
    }
  }
  return hits
}

// ── Rule Definitions (Classified by Capability / Indicator / Context) ────────
const RULES: Rule[] = [

  // ══════════════════════════════════════════════════════════════════════════
  // RANSOMWARE
  // ══════════════════════════════════════════════════════════════════════════

  {
    severity: 'critical', category: 'ransomware', evidenceType: 'indicator',
    title: 'Shadow Copy Deletion Command',
    check: (a) => {
      const found = matchStr(allStrings(a), [
        /vssadmin\s+delete\s+shadows/i,
        /wmic\s+shadowcopy\s+delete/i,
        /wbadmin\s+delete\s+catalog/i,
        /Get-WmiObject\s+Win32_ShadowCopy.*Delete/i,
      ])
      return found ? `"${found.slice(0, 100)}"` : false
    },
  },

  {
    severity: 'critical', category: 'ransomware', evidenceType: 'indicator',
    title: 'Boot Recovery Sabotage',
    check: (a) => {
      const found = matchStr(allStrings(a), [
        /bcdedit.*recoveryenabled\s+no/i,
        /bcdedit.*bootstatuspolicy/i,
        /reagentc(\.exe)?\s+\/disable/i,
      ])
      return found ? `"${found.slice(0, 100)}"` : false
    },
  },

  {
    severity: 'high', category: 'ransomware', evidenceType: 'capability',
    title: 'Cryptography API + File Enumeration Combo (Ransomware Pattern)',
    check: (a) => {
      const apis = apiSet(a)
      const cryptApis = ['CryptEncrypt', 'CryptGenKey', 'BCryptEncrypt',
        'BCryptGenRandom', 'BCryptOpenAlgorithmProvider', 'NCryptEncrypt',
        'NCryptImportKey', 'CryptAcquireContextA', 'CryptAcquireContextW', 'CryptCreateHash']
      const enumApis = ['FindFirstFileA', 'FindFirstFileW', 'FindNextFileA', 'FindNextFileW', 'FindFirstFileExW']
      const foundCrypt = cryptApis.filter(x => apis.has(x.toLowerCase()))
      const foundEnum  = enumApis.filter(x => apis.has(x.toLowerCase()))
      return (foundCrypt.length > 0 && foundEnum.length > 0)
        ? `Crypto: ${foundCrypt.join(', ')} | Enum: ${foundEnum.join(', ')}`
        : false
    },
  },

  {
    severity: 'high', category: 'ransomware', evidenceType: 'indicator',
    title: 'Tor Hidden Service Address (.onion)',
    check: (a) => {
      const found = allStrings(a).find(s => /[a-z2-7]{16,56}\.onion/i.test(s))
      return found ? `"${found.slice(0, 80)}"` : false
    },
  },

  {
    severity: 'high', category: 'ransomware', evidenceType: 'indicator',
    title: 'Ransom Note / Extortion Language',
    check: (a) => {
      const found = matchStr(allStrings(a), [
        /your files (have been|are) encrypted/i,
        /all your files/i,
        /to (recover|decrypt) your/i,
        /pay.*bitcoin/i,
        /send.*bitcoin/i,
        /how to (unlock|recover|decrypt)/i,
        /decrypt.*key/i,
        /unique (key|id)/i,
      ])
      return found ? `"${found.slice(0, 120)}"` : false
    },
  },

  {
    severity: 'medium', category: 'ransomware', evidenceType: 'capability',
    title: 'Cryptography APIs Imported',
    check: (a) => {
      const apis = apiSet(a)
      const cryptApis = ['CryptEncrypt', 'CryptGenKey', 'BCryptEncrypt',
        'BCryptGenRandom', 'NCryptEncrypt', 'CryptAcquireContextA', 'CryptAcquireContextW']
      const found = cryptApis.filter(x => apis.has(x.toLowerCase()))
      return found.length > 0 ? found.join(', ') : false
    },
  },

  {
    severity: 'medium', category: 'ransomware', evidenceType: 'capability',
    title: 'Network Drive Enumeration (Worm/Ransomware Propagation)',
    check: (a) => {
      const apis = apiSet(a)
      const found = ['WNetOpenEnumA', 'WNetOpenEnumW', 'WNetEnumResourceA', 'WNetEnumResourceW',
        'WNetAddConnection2W', 'WNetAddConnection2A', 'WNetGetConnectionA', 'WNetGetConnectionW']
        .filter(x => apis.has(x.toLowerCase()))
      return found.length > 0 ? found.join(', ') : false
    },
  },

  {
    severity: 'medium', category: 'ransomware', evidenceType: 'indicator',
    title: 'Known Ransomware File Extension Patterns',
    check: (a) => {
      const exts = ['.locked', '.crypt', '.enc', '.encrypted', '.locky', '.cerber',
        '.zepto', '.crypto', '.wncry', '.wnry', '.wcry', '.lockbit', '.blackcat',
        '.alphv', '.akira', '.play', '.clop', '.ryuk', '.conti']
      const s = allStrings(a)
      const found = exts.find(ext => s.some(v => v.toLowerCase().includes(ext)))
      return found ? `Extension "${found}" found in strings` : false
    },
  },

  // ══════════════════════════════════════════════════════════════════════════
  // INFOSTEALER (CREDENTIALS, COOKIES & SESSION THEFT)
  // ══════════════════════════════════════════════════════════════════════════

  {
    severity: 'critical', category: 'infostealer', evidenceType: 'indicator',
    title: 'Browser Session Cookie & Credential Store Targeting (Infostealer)',
    check: (a) => {
      const hits = matchAllStr(allStrings(a), [
        /\\User Data\\Default\\Login Data/i,
        /\\User Data\\Default\\Network\\Cookies/i,
        /\\User Data\\Default\\Web Data/i,
        /\\User Data\\Local State/i,
        /Google\\Chrome\\User Data/i,
        /Microsoft\\Edge\\User Data/i,
        /BraveSoftware\\Brave-Browser\\User Data/i,
        /Opera Software\\Opera Stable/i,
        /cookies\.sqlite/i,
        /logins\.json/i,
        /key4\.db/i,
        /encrypted_value.*cookies/i,
        /SELECT\s+origin_url,\s*username_value,\s*password_value/i,
        /SELECT\s+host_key,\s*name,\s*encrypted_value\s+FROM\s+cookies/i,
      ])
      return hits.length > 0 ? `Browser stores targeted: ${hits.join(' | ')}` : false
    },
  },

  {
    severity: 'critical', category: 'infostealer', evidenceType: 'indicator',
    title: 'LSASS / SAM Credential Dumping Indicators',
    check: (a) => {
      const apis = apiSet(a)
      const hasMinidump = apis.has('minidumpwritedump')
      const credStrings = matchAllStr(allStrings(a), [
        /lsass\.exe/i,
        /sekurlsa::/i,
        /wdigest/i,
        /kerberos::/i,
        /\\System32\\config\\SAM/i,
        /\\System32\\config\\SECURITY/i,
        /reg\s+save\s+hklm\\sam/i,
        /reg\s+save\s+hklm\\security/i,
        /comsvcs\.dll.*MiniDump/i,
      ])
      if (hasMinidump && credStrings.length > 0) {
        return `MiniDumpWriteDump + ${credStrings.join(', ')}`
      }
      return credStrings.length > 0 ? credStrings.join(' | ') : false
    },
  },

  {
    severity: 'high', category: 'infostealer', evidenceType: 'capability',
    title: 'Windows DPAPI & Credential Vault Extraction',
    check: (a) => {
      const apis = apiSet(a)
      const dpapiFound = [
        'CryptUnprotectData',
        'CryptUnprotectMemory',
        'CredEnumerateA',
        'CredEnumerateW',
        'CredReadA',
        'CredReadW',
        'VaultEnumerateItems',
        'VaultGetItem',
        'VaultOpenVault',
      ].filter(x => apis.has(x.toLowerCase()))

      const strHits = matchAllStr(allStrings(a), [
        /CryptUnprotectData/i,
        /dpapi/i,
        /os_crypt.*encrypted_key/i,
        /Windows Credentials/i,
        /vaultcli\.dll/i,
      ])

      if (dpapiFound.length > 0) {
        return `APIs: ${dpapiFound.join(', ')}${strHits.length ? ` | Strings: ${strHits.join(', ')}` : ''}`
      }
      return strHits.length >= 2 ? `Strings: ${strHits.join(' | ')}` : false
    },
  },

  {
    severity: 'high', category: 'infostealer', evidenceType: 'indicator',
    title: 'Session Token & Messenger Account Hijacking (Discord / Telegram / Steam)',
    check: (a) => {
      const hits = matchAllStr(allStrings(a), [
        /\\discord\\Local Storage\\leveldb/i,
        /\\discordcanary\\Local Storage\\leveldb/i,
        /\\discordptb\\Local Storage\\leveldb/i,
        /dQw4w9WgXcQ:/i,
        /Telegram Desktop\\tdata/i,
        /\\Steam\\config\\loginusers\.vdf/i,
        /\.ROBLOSECURITY/i,
        /api\/v9\/users\/@me/i,
      ])
      return hits.length > 0 ? `Session paths: ${hits.join(' | ')}` : false
    },
  },

  {
    severity: 'high', category: 'infostealer', evidenceType: 'indicator',
    title: 'Cryptocurrency Wallet & Browser Extension Theft',
    check: (a) => {
      const hits = matchAllStr(allStrings(a), [
        /nkbihfbeogaeaoehlefnkodbefgpgknn/i,
        /bfnaelmomeimhlpmgjnjophhpkkoljpa/i,
        /hnfanknocfeofbddgcijnmhnfnkdnaad/i,
        /\\Exodus\\exodus\.wallet/i,
        /\\Electrum\\wallets/i,
        /\\Ethereum\\keystore/i,
        /\\atomic\\Local Storage\\leveldb/i,
        /wallet\.dat/i,
        /seed\.seco/i,
      ])
      return hits.length > 0 ? `Wallet targets: ${hits.join(' | ')}` : false
    },
  },

  {
    severity: 'medium', category: 'infostealer', evidenceType: 'capability',
    title: 'Keystroke & Clipboard Hijacking APIs (Keylogger / Clipper)',
    check: (a) => {
      const apis = apiSet(a)
      const keyApis = ['GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState', 'MapVirtualKeyA', 'MapVirtualKeyW']
        .filter(x => apis.has(x.toLowerCase()))
      const clipApis = ['GetClipboardData', 'SetClipboardData', 'OpenClipboard', 'AddClipboardFormatListener']
        .filter(x => apis.has(x.toLowerCase()))
      if (keyApis.length >= 2 && clipApis.length >= 1) {
        return `Keylogger (${keyApis.join(', ')}) + Clipboard (${clipApis.join(', ')})`
      }
      if (clipApis.includes('GetClipboardData') && clipApis.includes('SetClipboardData')) {
        return `Clipboard Hijacker / Crypto Clipper: ${clipApis.join(', ')}`
      }
      return false
    },
  },

  // ══════════════════════════════════════════════════════════════════════════
  // PACKER / OBFUSCATION
  // ══════════════════════════════════════════════════════════════════════════

  {
    severity: 'high', category: 'packer', evidenceType: 'indicator',
    title: 'High-Entropy Executable Section (Packed / Encrypted Payload)',
    check: (a) => {
      const s = a.sections.find(sec =>
        sec.entropy >= 7.5 && sec.rawSize > 4096 && sec.flags.includes('EXECUTE'))
      return s ? `"${s.name || '(unnamed)'}" — ${s.entropy.toFixed(3)} bits/byte` : false
    },
  },

  {
    severity: 'medium', category: 'packer', evidenceType: 'indicator',
    title: 'Section Virtual vs. Raw Size Discrepancy (Unpacking Stub)',
    check: (a) => {
      const s = a.sections.find(sec => sec.isAnomalousSize && sec.flags.includes('EXECUTE'))
      return s
        ? `Section "${s.name || '(unnamed)'}" VirtualSize (${s.virtualSize.toLocaleString()} B) >> RawSize (${s.rawSize.toLocaleString()} B)`
        : false
    },
  },

  {
    severity: 'medium', category: 'packer', evidenceType: 'indicator',
    title: 'High-Entropy Data Section',
    check: (a) => {
      const s = a.sections.find(sec =>
        sec.entropy >= 7.2 && sec.rawSize > 4096 && !sec.flags.includes('EXECUTE'))
      return s ? `"${s.name || '(unnamed)'}" — ${s.entropy.toFixed(3)} bits/byte` : false
    },
  },

  {
    severity: 'high', category: 'packer', evidenceType: 'indicator',
    title: 'Known Packer / Protector Section Name',
    check: (a) => {
      const known = ['upx0', 'upx1', 'upx2', '.packed', '.shrink', '.enigma1', '.enigma2',
        'aspack', '.aspack', '.adata', '.themida', 'vmprotect', '.vmp0', '.vmp1',
        '.nsp0', '.nsp1', '.petite', '.ccg', 'pebundle', 'bundle', '.mpress']
      const s = a.sections.find(sec => known.includes(sec.name.toLowerCase()))
      return s ? `Section "${s.name}"` : false
    },
  },

  {
    severity: 'medium', category: 'packer', evidenceType: 'capability',
    title: 'Only GetProcAddress / LoadLibrary Imports (Dynamic API Resolution)',
    check: (a) => {
      if (a.importedFunctions.length === 0 || a.importedFunctions.length > 12) return false
      const names = a.importedFunctions.map(f => f.name?.toLowerCase() ?? '')
      const dynamic = names.filter(n =>
        n.includes('getprocaddress') || n.includes('loadlibrary') ||
        n.includes('virtualalloc') || n.includes('heapalloc') ||
        n.includes('getmodulehandle'))
      return dynamic.length === names.length && dynamic.length > 0
        ? `${a.importedFunctions.length} import(s): ${names.filter(Boolean).join(', ')}`
        : false
    },
  },

  {
    severity: 'low', category: 'packer', evidenceType: 'context',
    title: 'File Overlay Detected (Data After Last Section)',
    check: (a) => a.overlay
      ? `${(a.overlay.size / 1024).toFixed(1)} KB at offset 0x${a.overlay.offset.toString(16).toUpperCase()}`
      : false,
  },

  {
    severity: 'low', category: 'packer', evidenceType: 'context',
    title: 'No Static Imports (Likely Packed / Statically Linked)',
    check: (a) => a.importedFunctions.length === 0
      ? 'No import table — may be packed, statically linked, or using manual API resolution'
      : false,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // PROCESS INJECTION
  // ══════════════════════════════════════════════════════════════════════════

  {
    severity: 'high', category: 'injection', evidenceType: 'capability',
    title: 'Classic Remote Process Injection APIs',
    check: (a) => {
      const apis = apiSet(a)
      const found = ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
        'NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtCreateThreadEx', 'RtlCreateUserThread']
        .filter(x => apis.has(x.toLowerCase()))
      return found.length >= 2 ? found.join(', ') : false
    },
  },

  {
    severity: 'high', category: 'injection', evidenceType: 'capability',
    title: 'DLL Injection via SetWindowsHookEx',
    check: (a) => {
      const apis = apiSet(a)
      const found = ['SetWindowsHookExA', 'SetWindowsHookExW']
        .filter(x => apis.has(x.toLowerCase()))
      return found.length > 0 ? found.join(', ') : false
    },
  },

  {
    severity: 'high', category: 'injection', evidenceType: 'capability',
    title: 'Process Hollowing (Unmap + Rewrite)',
    check: (a) => {
      const apis = apiSet(a)
      const found = ['NtUnmapViewOfSection', 'ZwUnmapViewOfSection',
        'NtMapViewOfSection', 'ZwMapViewOfSection']
        .filter(x => apis.has(x.toLowerCase()))
      return found.length > 0 ? found.join(', ') : false
    },
  },

  {
    severity: 'medium', category: 'injection', evidenceType: 'capability',
    title: 'Shared Memory / Fileless Injection APIs',
    check: (a) => {
      const apis = apiSet(a)
      const found = ['CreateFileMappingA', 'CreateFileMappingW',
        'MapViewOfFile', 'MapViewOfFileEx', 'OpenFileMappingA', 'OpenFileMappingW']
        .filter(x => apis.has(x.toLowerCase()))
      return found.length >= 2 ? found.join(', ') : false
    },
  },

  {
    severity: 'medium', category: 'injection', evidenceType: 'capability',
    title: 'APC Injection (QueueUserAPC)',
    check: (a) => {
      const apis = apiSet(a)
      return apis.has('queueuserapc') ? 'QueueUserAPC' : false
    },
  },

  // ══════════════════════════════════════════════════════════════════════════
  // PERSISTENCE
  // ══════════════════════════════════════════════════════════════════════════

  {
    severity: 'high', category: 'persistence', evidenceType: 'indicator',
    title: 'Registry Run Key / Startup Persistence',
    check: (a) => {
      const found = matchStr(allStrings(a), [
        /Software\\Microsoft\\Windows\\CurrentVersion\\Run/i,
        /Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon/i,
        /HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i,
        /HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution/i,
      ])
      return found ? `"${found.slice(0, 100)}"` : false
    },
  },

  {
    severity: 'medium', category: 'persistence', evidenceType: 'capability',
    title: 'Windows Service Installation',
    check: (a) => {
      const apis = apiSet(a)
      const found = ['CreateServiceA', 'CreateServiceW', 'ChangeServiceConfigA',
        'ChangeServiceConfigW', 'StartServiceCtrlDispatcherA', 'StartServiceCtrlDispatcherW']
        .filter(x => apis.has(x.toLowerCase()))
      return found.length > 0 ? found.join(', ') : false
    },
  },

  {
    severity: 'medium', category: 'persistence', evidenceType: 'indicator',
    title: 'Scheduled Task Strings',
    check: (a) => {
      const found = matchStr(allStrings(a), [
        /schtasks(\.exe)?(\s|$)/i,
        /ITaskScheduler/i,
        /SchRpcRegisterTask/i,
        /\\\\\$TASK\\/i,
      ])
      return found ? `"${found.slice(0, 80)}"` : false
    },
  },

  // ══════════════════════════════════════════════════════════════════════════
  // PRIVILEGE ESCALATION
  // ══════════════════════════════════════════════════════════════════════════

  {
    severity: 'high', category: 'privilege-escalation', evidenceType: 'capability',
    title: 'Token Privilege Manipulation',
    check: (a) => {
      const apis = apiSet(a)
      const found = ['AdjustTokenPrivileges', 'ImpersonateLoggedOnUser',
        'DuplicateTokenEx', 'CreateProcessWithTokenW', 'LsaAddAccountRights',
        'OpenProcessToken', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW']
        .filter(x => apis.has(x.toLowerCase()))
      return apis.has('adjusttokenprivileges') && found.length >= 2 ? found.join(', ') : false
    },
  },

  {
    severity: 'medium', category: 'privilege-escalation', evidenceType: 'indicator',
    title: 'SeDebugPrivilege Reference',
    check: (a) => {
      const found = allStrings(a).find(s => /SeDebugPrivilege/i.test(s))
      return found ? `"${found.slice(0, 80)}"` : false
    },
  },

  {
    severity: 'high', category: 'privilege-escalation', evidenceType: 'indicator',
    title: 'Known UAC Bypass Pattern',
    check: (a) => {
      const found = matchStr(allStrings(a), [
        /fodhelper\.exe/i,
        /eventvwr\.exe/i,
        /cmstp\.exe/i,
        /\{3E5FC7F9-9A51-4367-9063-A120244FBEC7\}/i,
        /DelegateExecute/i,
      ])
      return found ? `"${found.slice(0, 80)}"` : false
    },
  },

  {
    severity: 'low', category: 'privilege-escalation', evidenceType: 'context',
    title: 'Manifest Requests Administrator Elevation',
    check: (a) => a.embeddedManifest?.executionLevel === 'requireAdministrator'
      ? 'requestedExecutionLevel level="requireAdministrator" in embedded manifest'
      : false,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // ANTI-ANALYSIS / EVASION
  // ══════════════════════════════════════════════════════════════════════════

  {
    severity: 'medium', category: 'evasion', evidenceType: 'capability',
    title: 'Debugger Detection APIs',
    check: (a) => {
      const apis = apiSet(a)
      const found = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess', 'OutputDebugStringA', 'OutputDebugStringW']
        .filter(x => apis.has(x.toLowerCase()))
      return found.length > 0 ? found.join(', ') : false
    },
  },

  {
    severity: 'medium', category: 'evasion', evidenceType: 'indicator',
    title: 'VM / Sandbox Fingerprinting',
    check: (a) => {
      const vmStrings = matchStr(allStrings(a), [
        /vmware/i, /virtualbox/i, /vbox/i, /qemu/i,
        /sandboxie/i, /cuckoo/i, /wireshark/i, /processhacker/i,
      ])
      if (vmStrings) return `VM/sandbox artifact string: "${vmStrings.slice(0, 60)}"`
      const apis = apiSet(a)
      const sysEnumApis = ['GetSystemFirmwareTable', 'EnumDisplayDevices', 'GetAdaptersInfo',
        'GetAdaptersAddresses', 'GetSystemInfo', 'GlobalMemoryStatusEx']
        .filter(x => apis.has(x.toLowerCase()))
      return sysEnumApis.length >= 3 ? `System enumeration: ${sysEnumApis.join(', ')}` : false
    },
  },

  {
    severity: 'medium', category: 'evasion', evidenceType: 'capability',
    title: 'Timing-Based Anti-Sandbox (Sleep + Query)',
    check: (a) => {
      const apis = apiSet(a)
      const timing = ['GetTickCount', 'GetTickCount64', 'timeGetTime',
        'QueryPerformanceCounter', 'QueryPerformanceFrequency']
        .filter(x => apis.has(x.toLowerCase()))
      const hasSleep = apis.has('sleep') || apis.has('sleepex') || apis.has('waitmessage')
      return timing.length >= 2 && hasSleep ? `${timing.join(', ')} + Sleep` : false
    },
  },

  {
    severity: 'low', category: 'evasion', evidenceType: 'context',
    title: 'TLS Callbacks (Pre-EntryPoint Code Execution)',
    check: (a) => a.hasTlsCallbacks
      ? 'TLS callback directory present — code executes before main entry point'
      : false,
  },

  // ══════════════════════════════════════════════════════════════════════════
  // NETWORK / C2
  // ══════════════════════════════════════════════════════════════════════════

  {
    severity: 'high', category: 'network', evidenceType: 'capability',
    title: 'Reverse Shell Pattern (Socket + Process Creation)',
    check: (a) => {
      const apis = apiSet(a)
      const netApis = ['WSAStartup', 'socket', 'connect', 'WSASocketA', 'WSASocketW', 'WSAConnect']
        .filter(x => apis.has(x.toLowerCase()))
      const procApis = ['CreateProcessA', 'CreateProcessW', 'ShellExecuteA', 'ShellExecuteW',
        'WinExec', 'system']
        .filter(x => apis.has(x.toLowerCase()))
      return netApis.length > 0 && procApis.length > 0
        ? `Socket: ${netApis.slice(0, 3).join(', ')} | Process: ${procApis.slice(0, 2).join(', ')}`
        : false
    },
  },

  {
    severity: 'medium', category: 'network', evidenceType: 'capability',
    title: 'DNS Lookup + HTTP (Potential C2 Beacon)',
    check: (a) => {
      const apis = apiSet(a)
      const dns  = ['getaddrinfo', 'gethostbyname', 'DnsQuery_A', 'DnsQuery_W'].filter(x => apis.has(x.toLowerCase()))
      const http = ['HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA', 'HttpSendRequestW',
        'InternetOpenUrlA', 'InternetOpenUrlW', 'WinHttpOpen', 'WinHttpSendRequest']
        .filter(x => apis.has(x.toLowerCase()))
      return dns.length > 0 && http.length > 0
        ? `DNS: ${dns.join(', ')} | HTTP: ${http.join(', ')}`
        : false
    },
  },

  // ══════════════════════════════════════════════════════════════════════════
  // BINARY HARDENING & CONTEXT
  // ══════════════════════════════════════════════════════════════════════════

  {
    severity: 'low', category: 'general', evidenceType: 'indicator',
    title: 'Executable + Writable Section (W^X Violation)',
    check: (a) => {
      const s = a.sections.find(sec =>
        sec.flags.includes('EXECUTE') && sec.flags.includes('WRITE'))
      return s
        ? `Section "${s.name || '(unnamed)'}" is simultaneously executable and writable (${s.characteristics})`
        : false
    },
  },

  {
    severity: 'low', category: 'general', evidenceType: 'context',
    title: 'No ASLR (DYNAMIC_BASE not set)',
    check: (a) => !a.dllCharacteristics.some(d => d.includes('DYNAMIC_BASE'))
      ? 'Binary does not have ASLR enabled — fixed base address makes exploitation easier'
      : false,
  },

  {
    severity: 'low', category: 'general', evidenceType: 'context',
    title: 'No DEP / NX (NX_COMPAT not set)',
    check: (a) => !a.dllCharacteristics.some(d => d.includes('NX_COMPAT'))
      ? 'Binary does not have DEP/NX support — stack/heap shellcode execution is possible'
      : false,
  },

  {
    severity: 'informational', category: 'general', evidenceType: 'context',
    title: 'Not Authenticode Signed',
    check: (a) => !a.isAuthenticodeSigned
      ? 'No Authenticode certificate table found — unsigned binary'
      : 'Authenticode certificate table present (trust chain requires OS WinVerifyTrust validation)',
  },

  {
    severity: 'informational', category: 'general', evidenceType: 'context',
    title: '.NET Managed Assembly (CLR Header Present)',
    check: (a) => a.isDotNet
      ? 'CLR Runtime Header (Data Directory 14) present — inspectable with IL decompiler'
      : false,
  },

  {
    severity: 'informational', category: 'general', evidenceType: 'context',
    title: 'PDB Debug Path Exposed',
    check: (a) => a.pdbPath
      ? `"${a.pdbPath}"`
      : false,
  },

  {
    severity: 'informational', category: 'general', evidenceType: 'context',
    title: 'Static Analysis Only — Lab Validation Required',
    check: () =>
      'Static indicators show capabilities and artifacts, not confirmed execution. Correlate with runtime telemetry before automated blocking.',
  },
]

// ── Scoring & Explainable Decision Calibration ────────────────────────────────
const SEVERITY_SCORE: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 3,
  informational: 0,
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']

export function computeFindings(analysis: PartialAnalysis): {
  findings: Finding[]
  riskScore: number
  confidenceScore: number
  recommendedDecision: ResponseDecision
  decisionRationale: string
} {
  const findings: Finding[] = []

  for (const rule of RULES) {
    const evidence = rule.check(analysis)
    if (evidence !== false) {
      findings.push({
        severity: rule.severity,
        category: rule.category,
        evidenceType: rule.evidenceType,
        title: rule.title,
        evidence,
      })
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))

  const rawScore = findings.reduce((sum, f) => sum + SEVERITY_SCORE[f.severity], 0)
  const riskScore = Math.min(100, rawScore)

  // Explainable Confidence & Decision Policy:
  // Distinguish capabilities/context from concrete indicators
  const criticalIndicators = findings.filter(
    f => f.severity === 'critical' && f.evidenceType === 'indicator',
  )
  const highIndicators = findings.filter(
    f => f.severity === 'high' && f.evidenceType === 'indicator',
  )
  const capabilities = findings.filter(f => f.evidenceType === 'capability' && f.severity !== 'informational')
  const distinctThreatCategories = new Set(
    findings.filter(f => f.category !== 'general' && f.severity !== 'informational').map(f => f.category),
  )

  let confidenceScore = 15
  confidenceScore += criticalIndicators.length * 35
  confidenceScore += highIndicators.length * 20
  confidenceScore += Math.min(25, capabilities.length * 10)
  if (distinctThreatCategories.size >= 2) confidenceScore += 15
  if (!analysis.isAuthenticodeSigned && (criticalIndicators.length > 0 || highIndicators.length > 0)) {
    confidenceScore += 10
  }

  // If there are ONLY capabilities/context and ZERO specific indicators, cap confidence at 48%
  if (criticalIndicators.length === 0 && highIndicators.length === 0) {
    confidenceScore = Math.min(48, confidenceScore)
  }
  confidenceScore = Math.min(98, Math.max(10, confidenceScore))

  let recommendedDecision: ResponseDecision = 'observe'
  let decisionRationale =
    'Only low-risk or contextual PE traits identified. No destructive or credential-stealing indicators present.'

  if (
    criticalIndicators.length >= 1 &&
    (criticalIndicators.length >= 2 || highIndicators.length >= 1 || capabilities.length >= 1)
  ) {
    recommendedDecision = 'block'
    decisionRationale =
      'Multiple independent high-confidence indicators corroborated by capabilities. Isolate/quarantine sample and inspect host telemetry.'
  } else if (riskScore >= 25 || criticalIndicators.length >= 1 || highIndicators.length >= 1 || capabilities.length >= 2) {
    recommendedDecision = 'alert'
    decisionRationale =
      'Static capabilities or indicators justify manual analyst investigation, but do not alone prove active compromise without runtime telemetry.'
  }

  return {
    findings,
    riskScore,
    confidenceScore,
    recommendedDecision,
    decisionRationale,
  }
}
