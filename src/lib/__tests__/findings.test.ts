import { describe, expect, it } from 'vitest'
import { computeFindings } from '../findings'
import { translateRuleTitle } from '../i18n'
import type { PeAnalysis } from '../../types'

type PartialAnalysis = Omit<
  PeAnalysis,
  'findings' | 'riskScore' | 'confidenceScore' | 'recommendedDecision' | 'decisionRationale'
>

const createBaseAnalysis = (overrides?: Partial<PartialAnalysis>): PartialAnalysis => ({
  fileName: 'test.exe',
  fileSize: 102400,
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  md5: 'd41d8cd98f00b204e9800998ecf8427e',
  sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
  impHash: '1234567890abcdef1234567890abcdef',
  architecture: 'x64 (AMD64)',
  subsystem: 'Windows GUI',
  timestamp: new Date().toISOString(),
  entryPoint: '0x1000',
  imageBase: '0x140000000',
  sections: [
    {
      name: '.text',
      virtualAddress: '0x1000',
      virtualSize: 40960,
      rawSize: 40960,
      characteristics: '0x60000020',
      entropy: 6.2,
      flags: ['CODE', 'EXECUTE', 'READ'],
    },
  ],
  imports: ['kernel32.dll'],
  importedFunctions: [
    { dll: 'kernel32.dll', name: 'GetModuleHandleW' },
    { dll: 'kernel32.dll', name: 'ExitProcess' },
  ],
  exports: [],
  strings: ['Hello world', 'InternalName', 'ProductVersion'],
  unicodeStrings: ['Microsoft Corporation'],
  indicators: { urls: [], domains: [], paths: [], ips: [] },
  hasTlsCallbacks: false,
  isAuthenticodeSigned: true,
  authenticodeStatus: 'present_unverified',
  isDotNet: false,
  hasDelayImports: false,
  apiSetImports: [],
  dllCharacteristics: ['DYNAMIC_BASE (ASLR)', 'NX_COMPAT (DEP)'],
  ...overrides,
})

describe('findings heuristic engine', () => {
  it('assigns low risk to clean binary with basic imports and mitigations', () => {
    const analysis = createBaseAnalysis()
    const { findings, riskScore } = computeFindings(analysis)

    expect(riskScore).toBeLessThan(20)
    expect(findings.some(f => f.severity === 'critical' || f.severity === 'high')).toBe(false)
  })

  it('detects critical shadow copy deletion command (Ransomware)', () => {
    const analysis = createBaseAnalysis({
      strings: ['cmd.exe /c vssadmin delete shadows /all /quiet'],
    })
    const { findings, riskScore } = computeFindings(analysis)

    const vssFinding = findings.find(f => f.title.includes('Shadow Copy Deletion'))
    expect(vssFinding).toBeDefined()
    expect(vssFinding?.severity).toBe('critical')
    expect(vssFinding?.category).toBe('ransomware')
    expect(riskScore).toBeGreaterThanOrEqual(40)
  })

  it('detects boot recovery sabotage (Ransomware)', () => {
    const analysis = createBaseAnalysis({
      strings: ['bcdedit /set {default} recoveryenabled No'],
    })
    const { findings } = computeFindings(analysis)

    const bootFinding = findings.find(f => f.title.includes('Boot Recovery Sabotage'))
    expect(bootFinding).toBeDefined()
    expect(bootFinding?.severity).toBe('critical')
  })

  it('detects browser session cookie and credential store theft (Infostealer)', () => {
    const analysis = createBaseAnalysis({
      strings: [
        'C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies',
        'C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data',
        'C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Local State',
      ],
      importedFunctions: [
        { dll: 'crypt32.dll', name: 'CryptUnprotectData' },
      ],
    })
    const { findings, riskScore } = computeFindings(analysis)

    const cookieFinding = findings.find(f => f.category === 'infostealer' && f.title.includes('Browser Session Cookie'))
    const dpapiFinding  = findings.find(f => f.category === 'infostealer' && f.title.includes('DPAPI'))
    expect(cookieFinding).toBeDefined()
    expect(cookieFinding?.severity).toBe('critical')
    expect(dpapiFinding).toBeDefined()
    expect(dpapiFinding?.severity).toBe('high')
    expect(riskScore).toBeGreaterThanOrEqual(60)
  })

  it('detects Discord / Telegram session token hijacking and LSASS dumping', () => {
    const analysis = createBaseAnalysis({
      strings: [
        '\\discord\\Local Storage\\leveldb',
        'Telegram Desktop\\tdata',
        'lsass.exe',
      ],
      importedFunctions: [
        { dll: 'dbghelp.dll', name: 'MiniDumpWriteDump' },
      ],
    })
    const { findings } = computeFindings(analysis)

    const lsassFinding = findings.find(f => f.title.includes('LSASS / SAM Credential Dumping'))
    const tokenFinding = findings.find(f => f.title.includes('Session Token & Messenger'))
    expect(lsassFinding).toBeDefined()
    expect(lsassFinding?.severity).toBe('critical')
    expect(tokenFinding).toBeDefined()
    expect(tokenFinding?.severity).toBe('high')
  })

  it('detects high-severity cryptography + file enumeration pattern', () => {
    const analysis = createBaseAnalysis({
      importedFunctions: [
        { dll: 'advapi32.dll', name: 'CryptEncrypt' },
        { dll: 'advapi32.dll', name: 'CryptGenKey' },
        { dll: 'kernel32.dll', name: 'FindFirstFileW' },
        { dll: 'kernel32.dll', name: 'FindNextFileW' },
      ],
    })
    const { findings } = computeFindings(analysis)

    const cryptoEnumFinding = findings.find(f => f.title.includes('Cryptography API + File Enumeration'))
    expect(cryptoEnumFinding).toBeDefined()
    expect(cryptoEnumFinding?.severity).toBe('high')
  })

  it('detects process injection APIs combo (VirtualAllocEx + WriteProcessMemory)', () => {
    const analysis = createBaseAnalysis({
      importedFunctions: [
        { dll: 'kernel32.dll', name: 'VirtualAllocEx' },
        { dll: 'kernel32.dll', name: 'WriteProcessMemory' },
        { dll: 'kernel32.dll', name: 'CreateRemoteThread' },
      ],
    })
    const { findings } = computeFindings(analysis)

    const injectionFinding = findings.find(f => f.title.includes('Classic Remote Process Injection'))
    expect(injectionFinding).toBeDefined()
    expect(injectionFinding?.severity).toBe('high')
    expect(injectionFinding?.category).toBe('injection')
  })

  it('detects packed / encrypted executable sections with high entropy', () => {
    const analysis = createBaseAnalysis({
      sections: [
        {
          name: '.packed',
          virtualAddress: '0x1000',
          virtualSize: 65536,
          rawSize: 65536,
          characteristics: '0x60000020',
          entropy: 7.85,
          flags: ['CODE', 'EXECUTE', 'READ'],
        },
      ],
    })
    const { findings } = computeFindings(analysis)

    const packedSection = findings.find(f => f.title.includes('High-Entropy Executable Section'))
    expect(packedSection).toBeDefined()
    expect(packedSection?.severity).toBe('high')
  })

  it('translates rule titles accurately between English and Portuguese', () => {
    const enTitle = 'Browser Session Cookie & Credential Store Targeting (Infostealer)'
    expect(translateRuleTitle(enTitle, 'en')).toBe(enTitle)
    expect(translateRuleTitle(enTitle, 'pt')).toContain('Cookies de Sessão')
  })

  it('caps risk score at 100 max', () => {
    const analysis = createBaseAnalysis({
      strings: [
        'vssadmin delete shadows /all',
        'bcdedit /set {default} recoveryenabled No',
        'Your files have been encrypted! Send 1 BTC to unlock.',
        'http://x54abctest1234567.onion/pay',
      ],
      importedFunctions: [
        { dll: 'advapi32.dll', name: 'CryptEncrypt' },
        { dll: 'kernel32.dll', name: 'FindFirstFileW' },
        { dll: 'kernel32.dll', name: 'VirtualAllocEx' },
        { dll: 'kernel32.dll', name: 'WriteProcessMemory' },
      ],
    })
    const { riskScore, confidenceScore, recommendedDecision, findings } = computeFindings(analysis)
    expect(riskScore).toBe(100)
    expect(confidenceScore).toBeGreaterThanOrEqual(70)
    expect(recommendedDecision).toBe('block')
    expect(findings.every(f => ['capability', 'indicator', 'context', 'observed'].includes(f.evidenceType))).toBe(true)
  })
})
