import { describe, expect, it } from 'vitest'
import {
  deterministicUuid,
  escapeYaraString,
  sigmaRule,
  validateDetectionRules,
  yaraRule,
  yaraRuleBehavioral,
} from '../detections'
import type { PeAnalysis } from '../../types'

const mockAnalysis: PeAnalysis = {
  fileName: 'sample_payload.exe',
  fileSize: 204800,
  sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
  md5: '0123456789abcdef0123456789abcdef',
  sha1: '0123456789abcdef0123456789abcdef01234567',
  impHash: 'fedcba9876543210fedcba9876543210',
  architecture: 'x64 (AMD64)',
  subsystem: 'Windows GUI',
  timestamp: '2026-11-03T12:00:00.000Z',
  entryPoint: '0x1200',
  imageBase: '0x140000000',
  sections: [],
  imports: ['advapi32.dll'],
  importedFunctions: [
    { dll: 'advapi32.dll', name: 'CryptEncrypt' },
  ],
  exports: [],
  strings: ['vssadmin delete shadows /all /quiet', 'your files are encrypted'],
  unicodeStrings: [],
  indicators: { urls: [], domains: [], paths: [], ips: [] },
  findings: [
    {
      severity: 'critical',
      category: 'ransomware',
      evidenceType: 'indicator',
      title: 'Shadow Copy Deletion Command',
      evidence: 'vssadmin delete shadows',
    },
  ],
  riskScore: 85,
  confidenceScore: 88,
  recommendedDecision: 'block',
  decisionRationale: 'High confidence static indicators.',
  hasTlsCallbacks: false,
  isAuthenticodeSigned: false,
  authenticodeStatus: 'unsigned',
  isDotNet: false,
  hasDelayImports: false,
  apiSetImports: [],
  dllCharacteristics: [],
}

describe('detection rules generator', () => {
  it('generates valid YARA rule with metadata and hashes', () => {
    const yara = yaraRule(mockAnalysis)
    expect(yara).toContain('rule Sentinel_PE_sample_payload_exe')
    expect(yara).toContain(mockAnalysis.sha256)
    expect(yara).toContain(mockAnalysis.impHash)
    expect(yara).toContain('CryptEncrypt')
    expect(yara).toContain('any of ($api_*)')
    expect(yara).toContain('any of ($str_*)')
    expect(yara).toContain('condition:')
  })

  it('omits undefined string sets in YARA when no suspicious APIs or strings exist', () => {
    const cleanAnalysis: PeAnalysis = {
      ...mockAnalysis,
      impHash: '',
      importedFunctions: [{ dll: 'kernel32.dll', name: 'GetTickCount' }],
      strings: ['Normal application string'],
    }
    const yara = yaraRule(cleanAnalysis)
    expect(yara).not.toContain('strings:')
    expect(yara).not.toContain('$api_')
    expect(yara).not.toContain('$str_')
    expect(yara).not.toContain('imphash')
    expect(yara).toContain('uint16(0) == 0x5A4D')
  })

  it('generates behavioral YARA rule with valid threshold for 1 or 2+ strings', () => {
    const behavioralTwo = yaraRuleBehavioral(mockAnalysis)
    expect(behavioralTwo).toContain('rule Sentinel_Behavioral_sample_payload_exe')
    expect(behavioralTwo).toContain('vssadmin delete shadows')
    expect(behavioralTwo).toContain('2 of ($behavior_*)')

    const singleBehavior: PeAnalysis = {
      ...mockAnalysis,
      strings: ['vssadmin delete shadows /all'],
    }
    const behavioralOne = yaraRuleBehavioral(singleBehavior)
    expect(behavioralOne).toContain('any of ($behavior_*)')
    expect(behavioralOne).not.toContain('2 of ($behavior_*)')
  })

  it('escapes quotes, backslashes, and control characters in YARA strings', () => {
    const raw = 'C:\\Users\\"Admin"\\Login Data\r\n\t\x01'
    const escaped = escapeYaraString(raw)
    expect(escaped).toBe('C:\\\\Users\\\\\\"Admin\\"\\\\Login Data\\r\\n\\t\\x01')
  })

  it('generates valid Sigma rule with non-nil RFC-4122 UUID and omits empty IMPHASH', () => {
    const sigma = sigmaRule({ ...mockAnalysis, impHash: '' })
    expect(sigma).toContain('title: "Sentinel PE — sample_payload.exe"')
    expect(sigma).toContain('level: critical')
    expect(sigma).not.toContain('00000000-0000-0000-0000-000000000000')
    expect(sigma).toMatch(/id: [0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/)
    expect(sigma).toContain(`SHA256=${mockAnalysis.sha256.toUpperCase()}`)
    expect(sigma).not.toContain('IMPHASH=')
    expect(sigma).toContain('RANSOMWARE: Shadow Copy Deletion Command')
  })

  it('produces deterministic valid v4 UUIDs from SHA-256 hashes', () => {
    const u1 = deterministicUuid(mockAnalysis.sha256)
    const u2 = deterministicUuid(mockAnalysis.sha256)
    expect(u1).toBe(u2)
    expect(u1).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  })

  it('validates generated YARA and Sigma rules in the Rule Test Lab', () => {
    const validation = validateDetectionRules(mockAnalysis)
    expect(validation.yaraValid).toBe(true)
    expect(validation.sigmaValid).toBe(true)
    expect(validation.matchesCurrentSample).toBe(true)
    expect(validation.matchedStringsCount).toBeGreaterThanOrEqual(2)
    expect(validation.warnings).toEqual([])
  })
})
