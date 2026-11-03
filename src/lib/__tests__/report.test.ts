import { describe, expect, it } from 'vitest'
import { markdownReport } from '../report'
import type { PeAnalysis } from '../../types'

const sampleAnalysis: PeAnalysis = {
  fileName: 'suspect.exe',
  fileSize: 65536,
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  md5: 'd41d8cd98f00b204e9800998ecf8427e',
  sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
  impHash: '1234567890abcdef1234567890abcdef',
  architecture: 'x64 (AMD64)',
  subsystem: 'Windows Console (CUI)',
  timestamp: '2026-11-03T12:00:00.000Z',
  entryPoint: '0x1000',
  imageBase: '0x140000000',
  sections: [],
  imports: ['kernel32.dll'],
  importedFunctions: [{ dll: 'kernel32.dll', name: 'VirtualAllocEx' }],
  exports: [],
  strings: ['vssadmin delete shadows /all'],
  unicodeStrings: [],
  indicators: { urls: [], domains: [], paths: [], ips: [] },
  findings: [
    {
      severity: 'critical',
      category: 'ransomware',
      evidenceType: 'indicator',
      title: 'Shadow Copy Deletion Command',
      evidence: 'vssadmin delete shadows /all',
    },
  ],
  riskScore: 90,
  confidenceScore: 86,
  recommendedDecision: 'block',
  decisionRationale: 'High-specificity static indicators detected.',
  hasTlsCallbacks: false,
  isAuthenticodeSigned: false,
  authenticodeStatus: 'unsigned',
  isDotNet: false,
  hasDelayImports: false,
  apiSetImports: [],
  dllCharacteristics: ['DYNAMIC_BASE (ASLR)'],
}

describe('forensic report generator', () => {
  it('includes chain-of-custody, explainable confidence, and evidence type in Markdown report', () => {
    const md = markdownReport(sampleAnalysis)
    expect(md).toContain('# Sentinel PE — Relatório de Triagem Explicável & Cadeia de Custódia')
    expect(md).toContain('Chain of Custody')
    expect(md).toContain('86%')
    expect(md).toContain('ISOLAR / QUARENTENAR')
    expect(md).toContain('INDICATOR')
    expect(md).toContain(sampleAnalysis.sha256)
  })
})
