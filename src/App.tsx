import { useCallback, useEffect, useRef, useState } from 'react'
import { analyzePortableExecutable } from './lib/pe-parser'
import { downloadJsonReport, markdownReport } from './lib/report'
import { downloadText, sigmaRule, validateDetectionRules, yaraRule, yaraRuleBehavioral } from './lib/detections'
import { correlateTelemetryEvents, importTelemetry } from './lib/telemetry'
import {
  categoryLabels,
  decisionLabels,
  evidenceTypeLabels,
  severityLabels,
  translateRuleTitle,
  translations,
} from './lib/i18n'
import type {
  ExportedFunction,
  Finding,
  FindingCategory,
  GuardStatus,
  ImportedFunction,
  Language,
  PeAnalysis,
  ResponseDecision,
  Severity,
  SuspiciousProcess,
  TelemetryEvent,
} from './types'

// ── Clean Vector SVG Icons (Zero Emojis) ──────────────────────────────────────
const IconShield = ({ size = 18 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
)

const IconShieldCheck = ({ size = 28 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="m9 12 2 2 4-4" />
  </svg>
)

const IconShieldAlert = ({ size = 28 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <line x1="12" y1="8" x2="12" y2="12" />
    <line x1="12" y1="16" x2="12.01" y2="16" />
  </svg>
)

const IconScanner = ({ size = 16 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <polyline points="14 2 14 8 20 8" />
    <line x1="9" y1="13" x2="15" y2="13" />
    <line x1="9" y1="17" x2="13" y2="17" />
  </svg>
)

const IconVault = ({ size = 16 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
)

const IconFolder = ({ size = 15 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
  </svg>
)

const IconUpload = ({ size = 15 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="17 8 12 3 7 8" />
    <line x1="12" y1="3" x2="12" y2="15" />
  </svg>
)

const IconActivity = ({ size = 15 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
  </svg>
)

const IconCheck = ({ size = 14 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
)

const IconX = ({ size = 14 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="#e3b341" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="6" x2="6" y2="18" />
    <line x1="6" y1="6" x2="18" y2="18" />
  </svg>
)

const IconCopy = ({ size = 13 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </svg>
)

const IconExternal = ({ size = 12 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
    <polyline points="15 3 21 3 21 9" />
    <line x1="10" y1="14" x2="21" y2="3" />
  </svg>
)

// ── Formatters ─────────────────────────────────────────────────────────────────
const fmtBytes = (n: number) =>
  n >= 1048576 ? `${(n / 1048576).toFixed(2)} MB` :
  n >= 1024    ? `${(n / 1024).toFixed(1)} KB` :
  `${n} B`

const copyToClipboard = (text: string) => navigator.clipboard.writeText(text).catch(() => null)

const DEFAULT_GUARD_STATUS: GuardStatus = {
  enabled: false,
  autoQuarantine: false,
  canaryEnabled: false,
  canaryStatus: 'disabled',
  watchedFolders: [],
  canaryFiles: [],
  filesScannedCount: 0,
  threatsBlockedCount: 0,
  alerts: [],
  quarantine: [],
}

type ScannerSubTab = 'overview' | 'structure' | 'imports' | 'strings' | 'rules' | 'all'

// ── Shared UI Components ──────────────────────────────────────────────────────
function CopyBtn({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    void copyToClipboard(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1400)
  }
  return (
    <button className="copy-btn" onClick={handleCopy} title="Copy">
      {copied ? <IconCheck size={13} /> : <IconCopy size={13} />}
    </button>
  )
}

function Metric({ label, value, mono = false, highlight }: {
  label: string
  value: string
  mono?: boolean
  highlight?: 'ok' | 'danger' | 'warn'
}) {
  return (
    <article className={`metric ${highlight ? `metric-${highlight}` : ''}`}>
      <p>{label}</p>
      <strong className={mono ? 'mono' : ''}>{value}</strong>
    </article>
  )
}

function AssessmentStrip({
  analysis,
  lang,
}: {
  analysis: PeAnalysis
  lang: Language
}) {
  const t = translations[lang]
  const { riskScore, confidenceScore, recommendedDecision, decisionRationale, findings } = analysis
  const scoreColor =
    riskScore >= 80 ? '#f85149' :
    riskScore >= 50 ? '#ffa657' :
    riskScore >= 20 ? '#e3b341' :
    '#10b981'
  const scoreLabel =
    riskScore >= 80 ? t.riskCritical :
    riskScore >= 50 ? t.riskHigh :
    riskScore >= 20 ? t.riskMedium :
    t.riskLow

  const decColor =
    recommendedDecision === 'block' ? '#ff7b72' :
    recommendedDecision === 'alert' ? '#ffa657' :
    '#34d399'

  const ransomwareHits = findings.filter(f => f.category === 'ransomware')
  const stealerHits    = findings.filter(f => f.category === 'infostealer')
  const injectionHits  = findings.filter(f => f.category === 'injection' || f.category === 'packer' || f.category === 'evasion')

  const matrixItems = [
    { label: t.cardRansomware, hits: ransomwareHits },
    { label: t.cardInfostealer, hits: stealerHits },
    { label: t.cardInjection, hits: injectionHits },
  ]

  return (
    <div className="assessment-strip">
      {/* Column 1: Score & Confidence */}
      <article className="score-box">
        <div>
          <p className="panel-label">{t.riskScoreLabel}</p>
          <div className="score-readout">
            <span className="score-number" style={{ color: scoreColor }}>{riskScore}<small style={{ fontSize: 13, color: '#7d8590' }}>/100</small></span>
            <span style={{ fontSize: 12, fontWeight: 700, color: scoreColor }}>{scoreLabel}</span>
          </div>
          <div className="score-bar-track">
            <div className="score-bar-fill" style={{ width: `${riskScore}%`, background: scoreColor }} />
          </div>
        </div>
        <div className="confidence-row">
          <span>{t.confidenceLabel}</span>
          <strong className="mono" style={{ color: '#e6edf3' }}>{confidenceScore}%</strong>
        </div>
      </article>

      {/* Column 2: Operational Decision & Rationale */}
      <article className="decision-box">
        <div>
          <p className="panel-label">{t.decisionLabel}</p>
          <div style={{ marginBottom: 8 }}>
            <span className="decision-pill" style={{ color: decColor, borderColor: decColor }}>
              {decisionLabels[lang][recommendedDecision]}
            </span>
          </div>
          <p style={{ margin: 0, fontSize: 12, color: '#8b949e', lineHeight: 1.45 }}>
            {decisionRationale}
          </p>
        </div>
      </article>

      {/* Column 3: Threat Domain Matrix */}
      <article className="threat-matrix-box">
        {matrixItems.map(({ label, hits }) => {
          const hasCrit = hits.some(h => h.severity === 'critical' || h.severity === 'high')
          const hasAny = hits.length > 0
          return (
            <div
              key={label}
              className={`matrix-row ${hasCrit ? 'hit-danger' : hasAny ? 'hit-warn' : ''}`}
            >
              <span style={{ color: '#c9d1d9', fontWeight: 500 }}>{label}</span>
              <strong
                className="mono"
                style={{
                  fontSize: 11,
                  color: hasCrit ? '#ff7b72' : hasAny ? '#e3b341' : '#34d399',
                }}
              >
                {hasAny ? `${hits.length} ${t.statusDetected}` : t.statusClean}
              </strong>
            </div>
          )
        })}
      </article>
    </div>
  )
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']
const SEV_COLOR: Record<Severity, string> = {
  critical: '#ff7b72', high: '#ffa657', medium: '#e3b341',
  low: '#56d4dd', informational: '#79c0ff',
}

function FindingsPanel({ findings, lang }: { findings: Finding[]; lang: Language }) {
  const t = translations[lang]
  const [activeSev, setActiveSev] = useState<Severity | 'all'>('all')
  const [activeCat, setActiveCat] = useState<FindingCategory | 'all'>('all')

  const counts = SEVERITIES.reduce<Record<Severity, number>>((acc, s) => {
    acc[s] = findings.filter(f => f.severity === s).length
    return acc
  }, {} as Record<Severity, number>)

  const presentCategories = [...new Set(findings.map(f => f.category))]

  const visible = findings.filter(f =>
    (activeSev === 'all' || f.severity === activeSev) &&
    (activeCat === 'all' || f.category === activeCat)
  )

  return (
    <article className="panel">
      <div className="panel-title">
        <h3><IconActivity size={15} /> {t.findingsTitle}</h3>
        <span className="panel-count">{findings.length}</span>
      </div>

      <div className="sev-filter">
        <button className={`sev-btn ${activeSev === 'all' ? 'active' : ''}`} onClick={() => setActiveSev('all')}>
          {t.filterAll} <em>{findings.length}</em>
        </button>
        {SEVERITIES.filter(s => counts[s] > 0).map(s => (
          <button key={s} className={`sev-btn ${activeSev === s ? 'active' : ''}`}
            style={{ '--sev-color': SEV_COLOR[s] } as React.CSSProperties}
            onClick={() => setActiveSev(s)}>
            {severityLabels[lang][s]} <em>{counts[s]}</em>
          </button>
        ))}

        {presentCategories.length > 1 && (
          <select
            className="cat-select"
            value={activeCat}
            onChange={e => setActiveCat(e.target.value as FindingCategory | 'all')}
          >
            <option value="all">{t.filterAll} ({presentCategories.length})</option>
            {presentCategories.map(c => (
              <option key={c} value={c}>{categoryLabels[lang][c]}</option>
            ))}
          </select>
        )}
      </div>

      <ul className="findings-list">
        {visible.map((f, i) => (
          <li key={`${f.title}-${i}`}>
            <div className="finding-header">
              <b className={`severity ${f.severity}`}>{severityLabels[lang][f.severity]}</b>
              <span className={`finding-cat cat-${f.category}`}>{categoryLabels[lang][f.category]}</span>
              <span className={`evidence-type ev-${f.evidenceType}`}>
                {evidenceTypeLabels[lang][f.evidenceType]}
              </span>
              <span className="finding-title">{translateRuleTitle(f.title, lang)}</span>
            </div>
            {f.evidence && <small className="finding-evidence">{f.evidence}</small>}
          </li>
        ))}
        {visible.length === 0 && <li className="empty-item">{t.noFindingsInCat}</li>}
      </ul>
    </article>
  )
}

function RuleTestLabPanel({ analysis, lang }: { analysis: PeAnalysis; lang: Language }) {
  const t = translations[lang]
  const validation = validateDetectionRules(analysis)
  const [showPreview, setShowPreview] = useState<'yara' | 'sigma'>('yara')
  const fullYara = yaraRule(analysis) + yaraRuleBehavioral(analysis)
  const fullSigma = sigmaRule(analysis)

  return (
    <article className="panel">
      <div className="panel-title">
        <h3>{t.ruleLabTitle}</h3>
        <div className="actions">
          <button
            className={`ghost-sm ${showPreview === 'yara' ? 'active' : ''}`}
            onClick={() => setShowPreview('yara')}
          >
            YARA
          </button>
          <button
            className={`ghost-sm ${showPreview === 'sigma' ? 'active' : ''}`}
            onClick={() => setShowPreview('sigma')}
          >
            Sigma YAML
          </button>
        </div>
      </div>

      <div className="two-column" style={{ marginBottom: 12 }}>
        <div className={`metric ${validation.yaraValid && validation.matchesCurrentSample ? 'metric-ok' : 'metric-danger'}`}>
          <p>YARA ({validation.matchedStringsCount} matched strings)</p>
          <strong>{validation.yaraValid && validation.matchesCurrentSample ? t.ruleLabYaraOk : validation.warnings.join(', ')}</strong>
        </div>
        <div className={`metric ${validation.sigmaValid ? 'metric-ok' : 'metric-danger'}`}>
          <p>Sigma YAML (RFC-4122 UUID v4)</p>
          <strong>{validation.sigmaValid ? t.ruleLabSigmaOk : validation.warnings.join(', ')}</strong>
        </div>
      </div>

      <pre className="rule-preview">
        <code>{showPreview === 'yara' ? fullYara : fullSigma}</code>
      </pre>
    </article>
  )
}

function HashesPanel({ analysis, lang }: { analysis: PeAnalysis; lang: Language }) {
  const t = translations[lang]
  const [compareInput, setCompareInput] = useState('')

  const hashes = [
    { label: 'SHA-256', value: analysis.sha256 },
    { label: 'SHA-1',   value: analysis.sha1 },
    { label: 'MD5',     value: analysis.md5 },
    ...(analysis.impHash ? [{ label: 'ImpHash', value: analysis.impHash }] : []),
    ...(analysis.richHeaderHash ? [{ label: 'Rich Header', value: analysis.richHeaderHash }] : []),
  ]

  const normCompare = compareInput.trim().toLowerCase()
  const isMatch = normCompare.length > 0 && hashes.some(h => h.value.toLowerCase() === normCompare)

  return (
    <article className="panel">
      <div className="panel-title">
        <h3>{t.hashesTitle}</h3>
        <div className="actions">
          <a className="ghost-sm"
            href={`https://www.virustotal.com/gui/file/${analysis.sha256}`}
            target="_blank" rel="noreferrer noopener">
            VirusTotal <IconExternal />
          </a>
          <a className="ghost-sm"
            href={`https://bazaar.abuse.ch/browse.php?search=sha256%3A${analysis.sha256}`}
            target="_blank" rel="noreferrer noopener">
            MalwareBazaar <IconExternal />
          </a>
        </div>
      </div>

      <div className="hash-grid">
        {hashes.map(({ label, value }) => (
          <div key={label} className="hash-row">
            <span className="hash-label">{label}</span>
            <code className="hash-value">{value}</code>
            <CopyBtn value={value} />
          </div>
        ))}
      </div>

      <div className="hash-compare-box">
        <input
          className="search-input"
          style={{ marginBottom: 0 }}
          placeholder={t.hashComparePlaceholder}
          value={compareInput}
          onChange={e => setCompareInput(e.target.value)}
        />
        {normCompare.length > 0 && (
          <p className={`hash-compare-result ${isMatch ? 'match' : 'mismatch'}`}>
            {isMatch ? t.hashMatch : t.hashMismatch}
          </p>
        )}
      </div>
    </article>
  )
}

function SectionsTable({ sections, lang }: { sections: PeAnalysis['sections']; lang: Language }) {
  const t = translations[lang]
  return (
    <article className="panel">
      <div className="panel-title">
        <h3>{t.sectionsTitle}</h3>
        <span className="panel-count">{sections.length}</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{t.colSecName}</th><th>{t.colSecRva}</th><th>{t.colSecVirtual}</th>
              <th>{t.colSecRaw}</th><th>{t.colSecEntropy}</th><th>{t.colSecFlags}</th>
            </tr>
          </thead>
          <tbody>
            {sections.map((s, i) => (
              <tr key={i} className={s.entropy >= 7.5 ? 'row-danger' : s.entropy >= 7.2 ? 'row-warn' : ''}>
                <td><code>{s.name || '—'}</code></td>
                <td><code>{s.virtualAddress}</code></td>
                <td className="mono">{s.virtualSize.toLocaleString()}</td>
                <td className="mono">{s.rawSize.toLocaleString()}</td>
                <td className={`mono ${s.entropy >= 7.5 ? 'text-danger' : s.entropy >= 7.2 ? 'text-warn' : ''}`}>
                  {s.entropy.toFixed(3)}
                </td>
                <td className="flags-cell">
                  {s.flags.map(f => <span key={f} className="flag-badge">{f}</span>)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </article>
  )
}

function ImportsPanel({ functions, dlls, lang }: { functions: ImportedFunction[]; dlls: string[]; lang: Language }) {
  const t = translations[lang]
  const [search, setSearch] = useState('')
  const [view, setView] = useState<'functions' | 'dlls'>('functions')

  const filtered = functions.filter(f =>
    !search ||
    f.dll.toLowerCase().includes(search.toLowerCase()) ||
    (f.name ?? '').toLowerCase().includes(search.toLowerCase())
  ).slice(0, 500)

  return (
    <article className="panel">
      <div className="panel-title">
        <h3>{t.importsTitle}</h3>
        <div className="actions">
          <span className="panel-count">{functions.length} {t.functionsCount} · {dlls.length} DLLs</span>
          <button className={`ghost-sm ${view === 'dlls' ? 'active' : ''}`} onClick={() => setView('dlls')}>{t.btnDlls}</button>
          <button className={`ghost-sm ${view === 'functions' ? 'active' : ''}`} onClick={() => setView('functions')}>{t.btnFunctions}</button>
        </div>
      </div>

      {view === 'functions' && (
        <>
          <input className="search-input" placeholder={t.searchFunctionsPlaceholder}
            value={search} onChange={e => setSearch(e.target.value)} />
          <div className="table-wrap">
            <table>
              <thead><tr><th>DLL</th><th>API</th><th>Ordinal</th></tr></thead>
              <tbody>
                {filtered.map((f, i) => (
                  <tr key={i}>
                    <td><code className="text-muted">{f.dll}</code></td>
                    <td><code>{f.name ?? '—'}</code></td>
                    <td className="mono">{f.ordinal !== undefined ? f.ordinal : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {functions.length > 500 && (
            <p className="muted" style={{ paddingTop: 8 }}>
              {t.showingTop} 500 {t.ofTotal} {functions.length}.
            </p>
          )}
        </>
      )}

      {view === 'dlls' && (
        <ul className="list">
          {dlls.map(dll => <li key={dll} className="mono">{dll}</li>)}
          {!dlls.length && <li className="muted">{t.noImports}</li>}
        </ul>
      )}
    </article>
  )
}

function ExportsPanel({ exports, lang }: { exports: ExportedFunction[]; lang: Language }) {
  const t = translations[lang]
  if (!exports.length) {
    return (
      <article className="panel">
        <div className="panel-title"><h3>{t.exportsTitle}</h3><span className="panel-count">0</span></div>
        <p className="muted">{t.noExports}</p>
      </article>
    )
  }
  return (
    <article className="panel">
      <div className="panel-title"><h3>{t.exportsTitle}</h3><span className="panel-count">{exports.length}</span></div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Ordinal</th><th>API</th><th>RVA</th></tr></thead>
          <tbody>
            {exports.slice(0, 300).map((e, i) => (
              <tr key={i}>
                <td className="mono">{e.ordinal}</td>
                <td><code>{e.name ?? '—'}</code></td>
                <td><code>{e.rva}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </article>
  )
}

function StringsViewer({ ascii, unicode, lang }: { ascii: string[]; unicode: string[]; lang: Language }) {
  const t = translations[lang]
  const [search, setSearch] = useState('')
  const [tab, setTab] = useState<'ascii' | 'unicode'>('ascii')
  const src = tab === 'ascii' ? ascii : unicode
  const visible = search
    ? src.filter(s => s.toLowerCase().includes(search.toLowerCase()))
    : src

  return (
    <article className="panel">
      <div className="panel-title">
        <h3>{t.stringsTitle}</h3>
        <div className="actions">
          <span className="panel-count">{ascii.length} ASCII · {unicode.length} UTF-16</span>
          <button className={`ghost-sm ${tab === 'ascii' ? 'active' : ''}`} onClick={() => setTab('ascii')}>ASCII</button>
          <button className={`ghost-sm ${tab === 'unicode' ? 'active' : ''}`} onClick={() => setTab('unicode')}>Unicode</button>
        </div>
      </div>
      <input className="search-input" placeholder={t.searchStringsPlaceholder}
        value={search} onChange={e => setSearch(e.target.value)} />
      <div className="strings">
        {visible.length
          ? visible.slice(0, 300).map((s, i) => <code key={`${tab}-${i}`}>{s}</code>)
          : <p className="muted">{t.noStrings}</p>
        }
      </div>
      {visible.length > 300 && (
        <p className="muted" style={{ paddingTop: 8 }}>
          {t.showingTop} 300 {t.ofTotal} {visible.length}.
        </p>
      )}
    </article>
  )
}

function IndicatorsPanel({ indicators, lang }: { indicators: PeAnalysis['indicators']; lang: Language }) {
  const t = translations[lang]
  const total = indicators.urls.length + indicators.domains.length +
    indicators.paths.length + indicators.ips.length
  if (total === 0) return null

  return (
    <article className="panel">
      <div className="panel-title"><h3>{t.indicatorsTitle}</h3><span className="panel-count">{total}</span></div>
      {indicators.ips.length > 0 && (
        <div className="indicator-group">
          <p className="indicator-label">IPs ({indicators.ips.length})</p>
          {indicators.ips.map(v => <div key={v} className="indicator-item">{v}</div>)}
        </div>
      )}
      {indicators.urls.length > 0 && (
        <div className="indicator-group">
          <p className="indicator-label">URLs ({indicators.urls.length})</p>
          {indicators.urls.map(v => <div key={v} className="indicator-item">{v}</div>)}
        </div>
      )}
      {indicators.domains.length > 0 && (
        <div className="indicator-group">
          <p className="indicator-label">Domains ({indicators.domains.length})</p>
          {indicators.domains.map(v => <div key={v} className="indicator-item">{v}</div>)}
        </div>
      )}
      {indicators.paths.length > 0 && (
        <div className="indicator-group">
          <p className="indicator-label">Paths ({indicators.paths.length})</p>
          {indicators.paths.map(v => <div key={v} className="indicator-item">{v}</div>)}
        </div>
      )}
    </article>
  )
}

function MitigationsPanel({ dllChars, isAuthenticodeSigned, hasTls, lang }:
  { dllChars: string[]; isAuthenticodeSigned: boolean; hasTls: boolean; lang: Language }) {
  const t = translations[lang]
  const checks = [
    { label: 'WIN_CERTIFICATE Table Present (Unverified Chain)', ok: isAuthenticodeSigned },
    { label: 'ASLR (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)', ok: dllChars.some(d => d.includes('DYNAMIC_BASE')) },
    { label: 'DEP / NX (IMAGE_DLLCHARACTERISTICS_NX_COMPAT)', ok: dllChars.some(d => d.includes('NX_COMPAT')) },
    { label: 'Control Flow Guard (GUARD_CF)', ok: dllChars.some(d => d.includes('GUARD_CF')) },
    { label: 'High Entropy 64-bit VA (HIGH_ENTROPY_VA)', ok: dllChars.some(d => d.includes('HIGH_ENTROPY_VA')) },
    { label: 'No Structured Exception Handling (NO_SEH)', ok: dllChars.some(d => d.includes('NO_SEH')) },
    { label: 'No Pre-Entry TLS Callbacks', ok: !hasTls },
  ]

  return (
    <article className="panel">
      <div className="panel-title"><h3>{t.mitigationsTitle}</h3></div>
      <ul className="mitigations-list">
        {checks.map(({ label, ok }) => (
          <li key={label} className={ok ? 'mit-ok' : 'mit-missing'}>
            {ok ? <IconCheck /> : <IconX />}
            <span>{label}</span>
          </li>
        ))}
      </ul>
    </article>
  )
}

// ── Active Guard Dashboard Component (Enterprise Endpoint Console) ────────────
function ActiveGuardDashboard({
  guard,
  lang,
  onToggleConfig,
  onScanFolder,
  onSelectFile,
  onClearAlerts,
  onOpenQuarantine,
  onQuarantineFile,
}: {
  guard: GuardStatus
  lang: Language
  onToggleConfig: (cfg: { enabled?: boolean; autoQuarantine?: boolean; canaryEnabled?: boolean }) => void
  onScanFolder: () => void
  onSelectFile: () => void
  onClearAlerts: () => void
  onOpenQuarantine: () => void
  onQuarantineFile: (filePath: string, reason: string) => void
}) {
  const t = translations[lang]
  const [processes, setProcesses] = useState<SuspiciousProcess[]>([])
  const [loadingProcs, setLoadingProcs] = useState(false)

  const refreshProcesses = useCallback(async () => {
    if (!window.sentinelGuard) return
    setLoadingProcs(true)
    try {
      setProcesses(await window.sentinelGuard.listProcesses())
    } finally {
      setLoadingProcs(false)
    }
  }, [])

  useEffect(() => {
    void refreshProcesses()
  }, [refreshProcesses])

  const handleKill = async (pid: number, quarantineExe: boolean) => {
    if (!window.sentinelGuard) return
    await window.sentinelGuard.killProcess(pid, quarantineExe)
    await refreshProcesses()
  }

  const isAlertState = guard.canaryStatus === 'tampered'
  const bannerStateClass = isAlertState ? 'state-alert' : guard.enabled ? 'state-active' : 'state-idle'
  const emblemClass      = isAlertState ? 'alert' : guard.enabled ? 'active' : 'idle'

  return (
    <div>
      {/* Enterprise Security Status Banner */}
      <section className={`security-status-banner ${bannerStateClass}`}>
        <div className="status-banner-main">
          <div className={`status-emblem ${emblemClass}`}>
            {isAlertState ? <IconShieldAlert size={30} /> : <IconShieldCheck size={30} />}
          </div>
          <div className="status-banner-info">
            <h2>
              {isAlertState
                ? t.guardBannerAlertTitle
                : guard.enabled
                  ? t.guardBannerActiveTitle
                  : t.guardBannerIdleTitle}
            </h2>
            <p>
              {isAlertState
                ? t.guardBannerAlertDesc
                : guard.enabled
                  ? t.guardBannerActiveDesc
                  : t.guardBannerIdleDesc}
            </p>
            <div className="actions">
              <button className="btn-primary" onClick={onSelectFile}>
                <IconUpload size={14} /> {t.btnSelectFile}
              </button>
              <button className="btn-secondary" onClick={onScanFolder}>
                <IconFolder size={14} /> {t.btnScanFolder}
              </button>
            </div>
          </div>
        </div>

        {/* Protection Modules Switchboard */}
        <div className="status-banner-controls">
          <label className="module-toggle-row">
            <span>{t.guardRealtimeToggle}</span>
            <span className="toggle-switch">
              <input
                type="checkbox"
                checked={guard.enabled}
                onChange={e => onToggleConfig({ enabled: e.target.checked })}
              />
              <span className="toggle-slider" />
            </span>
          </label>

          <label className="module-toggle-row">
            <span>{t.guardCanaryToggle}</span>
            <span className="toggle-switch">
              <input
                type="checkbox"
                checked={guard.canaryEnabled}
                onChange={e => onToggleConfig({ canaryEnabled: e.target.checked })}
              />
              <span className="toggle-slider" />
            </span>
          </label>

          <div className="policy-note">
            <IconVault size={13} />
            <span>{t.guardAutoBlockToggle}</span>
          </div>
        </div>
      </section>

      {/* Telemetry Counters */}
      <div className="summary-subgrid">
        <Metric
          label={t.metricShield}
          value={guard.enabled ? t.metricShieldOn : t.metricShieldOff}
          highlight={guard.enabled ? 'ok' : undefined}
        />
        <Metric
          label={t.metricCanary}
          value={
            guard.canaryStatus === 'tampered'
              ? t.metricCanaryTampered
              : guard.canaryStatus === 'intact'
                ? t.metricCanaryIntact
                : t.metricCanaryOff
          }
          highlight={guard.canaryStatus === 'tampered' ? 'danger' : guard.canaryStatus === 'intact' ? 'ok' : undefined}
        />
        <Metric label={t.metricScanned} value={guard.filesScannedCount.toLocaleString()} mono />
        <Metric
          label={t.metricBlocked}
          value={guard.threatsBlockedCount.toLocaleString()}
          mono
          highlight={guard.threatsBlockedCount > 0 ? 'danger' : undefined}
        />
      </div>

      {/* Security Alerts Log */}
      <article className="panel">
        <div className="panel-title">
          <h3>{t.alertsTitle}</h3>
          <div className="actions">
            <span className="panel-count">{guard.alerts.length}</span>
            {guard.quarantine.length > 0 && (
              <button className="ghost-sm" onClick={onOpenQuarantine}>
                {t.navQuarantine} ({guard.quarantine.length})
              </button>
            )}
            {guard.alerts.length > 0 && (
              <button className="ghost-sm" onClick={onClearAlerts}>{t.btnClearAlerts}</button>
            )}
          </div>
        </div>

        {guard.alerts.length > 0 ? (
          <ul className="findings-list">
            {guard.alerts.map(a => (
              <li key={a.id}>
                <div className="finding-header">
                  <b className={`severity ${a.severity}`}>{severityLabels[lang][a.severity]}</b>
                  <span className={`finding-cat cat-${a.category}`}>{categoryLabels[lang][a.category]}</span>
                  <span className="action-badge">{a.actionTaken.toUpperCase()}</span>
                  <strong className="finding-title">{a.title}</strong>
                  {a.actionTaken === 'alerted' && a.filePath && !a.filePath.startsWith('PID:') && (
                    <button
                      className="ghost-sm danger-btn"
                      onClick={() => onQuarantineFile(a.filePath, a.details[0] ?? a.title)}
                    >
                      {t.btnQuarantineCurrent}
                    </button>
                  )}
                  <time className="mono" style={{ fontSize: 11, color: '#7d8590' }}>
                    {new Date(a.timestamp).toLocaleTimeString()}
                  </time>
                </div>
                <small className="finding-evidence">
                  <div><b>Target:</b> {a.filePath} (Score: {a.riskScore}/100)</div>
                  {a.details.map((d, idx) => <div key={idx}>• {d}</div>)}
                </small>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">{t.noAlerts}</p>
        )}
      </article>

      {/* Live Suspicious Process Monitor */}
      <article className="panel">
        <div className="panel-title">
          <h3>{t.processesTitle}</h3>
          <div className="actions">
            <span className="panel-count">{processes.length}</span>
            <button className="ghost-sm" onClick={() => void refreshProcesses()} disabled={loadingProcs}>
              {t.btnRefreshProcesses}
            </button>
          </div>
        </div>

        {processes.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t.colPid}</th>
                  <th>{t.colProcess}</th>
                  <th>{t.colPath}</th>
                  <th>{t.colRisk}</th>
                  <th>{t.colAction}</th>
                </tr>
              </thead>
              <tbody>
                {processes.map(p => (
                  <tr key={p.pid} className={p.riskLevel === 'high' ? 'row-danger' : 'row-warn'}>
                    <td><code>{p.pid}</code></td>
                    <td><strong>{p.name}</strong></td>
                    <td style={{ maxWidth: 340, overflow: 'hidden', textOverflow: 'ellipsis' }} title={p.commandLine}>
                      <code>{p.executablePath || p.commandLine}</code>
                    </td>
                    <td>
                      <b className={`severity ${p.riskLevel}`}>{p.riskLevel}</b>{' '}
                      <small>{p.reason}</small>
                    </td>
                    <td>
                      <div className="actions">
                        <button className="ghost-sm danger-btn" onClick={() => void handleKill(p.pid, false)}>
                          {t.btnKillProcess}
                        </button>
                        <button className="ghost-sm danger-btn" onClick={() => void handleKill(p.pid, true)}>
                          {t.btnKillAndQuarantine}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="muted">{t.noSuspiciousProcesses}</p>
        )}
      </article>

      {/* Monitored Folders & Canary Files */}
      <div className="two-column">
        <article className="panel">
          <div className="panel-title">
            <h3>{t.watchedFoldersTitle}</h3>
            <span className="panel-count">{guard.watchedFolders.length}</span>
          </div>
          <ul className="list">
            {guard.watchedFolders.map(f => <li key={f} className="mono"><IconFolder size={13} /> {f}</li>)}
            {guard.watchedFolders.length === 0 && <li className="muted">{t.metricShieldOff}</li>}
          </ul>
        </article>

        <article className="panel">
          <div className="panel-title">
            <h3>{t.canaryFilesTitle}</h3>
            <span className="panel-count">{guard.canaryFiles.length}</span>
          </div>
          <ul className="list">
            {guard.canaryFiles.map(f => <li key={f} className="mono"><IconShield size={13} /> {f}</li>)}
            {guard.canaryFiles.length === 0 && <li className="muted">{t.metricCanaryOff}</li>}
          </ul>
        </article>
      </div>
    </div>
  )
}

// ── Quarantine Vault Component ────────────────────────────────────────────────
function QuarantineView({
  guard,
  lang,
  onRestore,
  onDelete,
}: {
  guard: GuardStatus
  lang: Language
  onRestore: (id: string) => void
  onDelete: (id: string) => void
}) {
  const t = translations[lang]
  return (
    <article className="panel">
      <div className="panel-title">
        <h3><IconVault size={15} /> {t.quarantineTitle}</h3>
        <span className="panel-count">{guard.quarantine.length}</span>
      </div>

      {guard.quarantine.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t.colDate}</th>
                <th>{t.colFile}</th>
                <th>{t.colCategory}</th>
                <th>{t.colScore}</th>
                <th>SHA-256</th>
                <th>{t.colAction}</th>
              </tr>
            </thead>
            <tbody>
              {guard.quarantine.map(item => (
                <tr key={item.id}>
                  <td className="mono">{new Date(item.quarantinedAt).toLocaleString()}</td>
                  <td>
                    <strong>{item.fileName}</strong>
                    <small style={{ display: 'block', color: '#7d8590' }}>{item.originalPath}</small>
                  </td>
                  <td>
                    <span className={`finding-cat cat-${item.category}`}>
                      {categoryLabels[lang][item.category]}
                    </span>
                  </td>
                  <td><strong className="text-danger mono">{item.riskScore}/100</strong></td>
                  <td><code style={{ fontSize: 11 }}>{item.sha256.slice(0, 20)}…</code></td>
                  <td>
                    <div className="actions">
                      <button className="ghost-sm" onClick={() => onRestore(item.id)}>
                        {t.btnRestore}
                      </button>
                      <button className="ghost-sm danger-btn" onClick={() => onDelete(item.id)}>
                        {t.btnDeletePerm}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted">{t.noQuarantine}</p>
      )}
    </article>
  )
}

// ── Main Desktop Application ──────────────────────────────────────────────────
export default function App() {
  const inputRef     = useRef<HTMLInputElement>(null)
  const telemetryRef = useRef<HTMLInputElement>(null)

  const [lang, setLang] = useState<Language>(() => {
    const saved = localStorage.getItem('sentinel_lang')
    return saved === 'en' || saved === 'pt' ? saved : 'pt'
  })
  const [activeTab, setActiveTab] = useState<'guard' | 'scanner' | 'quarantine'>('guard')
  const [scannerSubTab, setScannerSubTab] = useState<ScannerSubTab>('overview')

  const [guard, setGuard]         = useState<GuardStatus>(DEFAULT_GUARD_STATUS)
  const [analysis, setAnalysis]   = useState<PeAnalysis>()
  const [history, setHistory]     = useState<PeAnalysis[]>([])
  const [events, setEvents]       = useState<TelemetryEvent[]>([])
  const [error, setError]         = useState<string>()
  const [loading, setLoading]     = useState(false)
  const [dragging, setDragging]   = useState(false)
  const [noticeMsg, setNoticeMsg] = useState<string>()

  const t = translations[lang]

  const toggleLang = (next: Language) => {
    setLang(next)
    localStorage.setItem('sentinel_lang', next)
  }

  useEffect(() => {
    if (!window.sentinelGuard) return
    void window.sentinelGuard.getStatus().then(setGuard)
    const unsub = window.sentinelGuard.onStatusUpdate(setGuard)
    return unsub
  }, [])

  const inspect = async (file?: File | null) => {
    if (!file) return
    setActiveTab('scanner')
    setScannerSubTab('overview')
    setLoading(true)
    setError(undefined)
    try {
      const result = await analyzePortableExecutable(file)
      setAnalysis(result)
      setHistory(prev => [result, ...prev.filter(x => x.sha256 !== result.sha256)].slice(0, 10))
    } catch (caught) {
      setAnalysis(undefined)
      setError(caught instanceof Error ? caught.message : 'Could not analyze binary.')
    } finally {
      setLoading(false)
    }
  }

  const loadTelemetry = async (file?: File | null) => {
    if (!file) return
    setError(undefined)
    try {
      setEvents(await importTelemetry(file))
      setScannerSubTab('rules')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Invalid telemetry JSON.')
    }
  }

  const handleToggleGuardConfig = async (cfg: {
    enabled?: boolean
    autoQuarantine?: boolean
    canaryEnabled?: boolean
  }) => {
    if (window.sentinelGuard) {
      setGuard(await window.sentinelGuard.setConfig(cfg))
    } else {
      setGuard(prev => ({ ...prev, ...cfg }))
    }
  }

  const handleScanFolder = async () => {
    if (!window.sentinelGuard) {
      inputRef.current?.click()
      return
    }
    const res = await window.sentinelGuard.scanDirectory()
    setNoticeMsg(
      lang === 'pt'
        ? `Varredura concluída: ${res.scanned} executáveis verificados, ${res.threats} ameaça(s) detectada(s).`
        : `Folder scan complete: ${res.scanned} binaries checked, ${res.threats} threat(s) detected.`
    )
    setTimeout(() => setNoticeMsg(undefined), 5000)
  }

  const handleQuarantineByPath = async (filePath: string, reason: string) => {
    if (!window.sentinelGuard) return
    setError(undefined)
    const res = await window.sentinelGuard.quarantineFile(filePath, reason)
    if (res.ok) {
      setNoticeMsg(
        lang === 'pt'
          ? 'Arquivo isolado com segurança no Cofre de Quarentena AES-256-GCM.'
          : 'File safely isolated in the AES-256-GCM Quarantine Vault.'
      )
      setTimeout(() => setNoticeMsg(undefined), 5000)
    } else if (res.error && !res.error.toLowerCase().includes('cancel')) {
      setError(res.error)
    }
  }

  const handleQuarantineCurrent = async () => {
    if (!analysis?.filePath) return
    await handleQuarantineByPath(
      analysis.filePath,
      `Manual quarantine from Static Inspector (Score ${analysis.riskScore}/100)`
    )
  }

  const handleRestoreQuarantine = async (id: string) => {
    if (!window.sentinelGuard) return
    setError(undefined)
    const res = await window.sentinelGuard.restoreQuarantine(id)
    if (res.ok) {
      setNoticeMsg(
        lang === 'pt'
          ? 'Arquivo restaurado com verificação de integridade SHA-256.'
          : 'File restored with SHA-256 integrity verification.'
      )
      setTimeout(() => setNoticeMsg(undefined), 5000)
    } else if (res.error && !res.error.toLowerCase().includes('cancel')) {
      setError(res.error)
    }
  }

  const handleDeleteQuarantine = async (id: string) => {
    if (!window.sentinelGuard) return
    setError(undefined)
    const res = await window.sentinelGuard.deleteQuarantine(id)
    if (res.ok) {
      setNoticeMsg(
        lang === 'pt'
          ? 'Arquivo removido permanentemente do cofre.'
          : 'File permanently deleted from quarantine vault.'
      )
      setTimeout(() => setNoticeMsg(undefined), 5000)
    } else if (res.error && !res.error.toLowerCase().includes('cancel')) {
      setError(res.error)
    }
  }

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(true)
  }, [])
  const onDragLeave = useCallback(() => setDragging(false), [])
  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    void inspect(e.dataTransfer.files?.[0])
  }, [])

  const headerTitle =
    activeTab === 'guard' ? t.guardTitle :
    activeTab === 'scanner' ? (analysis ? `${t.navScanner} — ${analysis.fileName}` : t.navScanner) :
    t.quarantineTitle

  const headerSubtitle =
    activeTab === 'guard' ? t.guardSubtitle :
    activeTab === 'scanner' ? t.privacyNote :
    t.quarantineSubtitle

  return (
    <div
      className="app-shell"
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
    >
      {dragging && (
        <div className="drop-overlay">
          <div className="drop-overlay-box">
            <IconUpload size={28} />
            <span>{t.dropOverlay}</span>
          </div>
        </div>
      )}

      {/* Hidden File Inputs */}
      <input
        ref={inputRef}
        type="file"
        accept=".exe,.dll,.sys,.scr,.ocx,.drv,.efi,.com,.cpl"
        onChange={e => void inspect(e.target.files?.[0])}
        hidden
      />
      <input
        ref={telemetryRef}
        type="file"
        accept="application/json,.json"
        onChange={e => void loadTelemetry(e.target.files?.[0])}
        hidden
      />

      {/* Left Sidebar Navigation */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-logo">
            <IconShield size={18} />
          </div>
          <div className="brand-text">
            <div className="brand-title">Sentinel <span>PE</span></div>
            <div className="brand-sub">Endpoint & Binary Triage</div>
          </div>
        </div>

        <div className="sidebar-section-label">Módulos</div>
        <nav className="sidebar-nav">
          <button
            className={`sidebar-item ${activeTab === 'guard' ? 'active' : ''}`}
            onClick={() => setActiveTab('guard')}
          >
            <span className="sidebar-icon"><IconShield size={16} /></span>
            <span>{t.navGuard}</span>
            {guard.alerts.length > 0 && (
              <span className="sidebar-badge danger">{guard.alerts.length}</span>
            )}
          </button>

          <button
            className={`sidebar-item ${activeTab === 'scanner' ? 'active' : ''}`}
            onClick={() => setActiveTab('scanner')}
          >
            <span className="sidebar-icon"><IconScanner size={16} /></span>
            <span>{t.navScanner}</span>
            {analysis && (
              <span className="sidebar-badge">{analysis.riskScore}</span>
            )}
          </button>

          <button
            className={`sidebar-item ${activeTab === 'quarantine' ? 'active' : ''}`}
            onClick={() => setActiveTab('quarantine')}
          >
            <span className="sidebar-icon"><IconVault size={16} /></span>
            <span>{t.navQuarantine}</span>
            {guard.quarantine.length > 0 && (
              <span className="sidebar-badge">{guard.quarantine.length}</span>
            )}
          </button>
        </nav>

        <div className="sidebar-section-label">Ações Rápidas</div>
        <div className="sidebar-actions">
          <button className="btn-primary" onClick={() => inputRef.current?.click()}>
            <IconUpload size={14} />
            <span>{t.btnSelectFile}</span>
          </button>
          <button className="btn-secondary" onClick={() => void handleScanFolder()}>
            <IconFolder size={14} />
            <span>{t.btnScanFolder}</span>
          </button>
        </div>

        <div className="sidebar-footer">
          <div className="engine-status-box">
            <span
              className={`status-dot ${
                guard.canaryStatus === 'tampered'
                  ? 'danger'
                  : guard.enabled
                    ? ''
                    : 'paused'
              }`}
            />
            <div className="engine-status-text">
              <strong>{guard.enabled ? t.statusActive : t.statusPaused}</strong>
              <span>{t.statusOffline}</span>
            </div>
          </div>

          <div className="sidebar-meta-row">
            <span className="version-tag">v0.3.0 · x64</span>
            <div className="lang-switch">
              <button className={lang === 'pt' ? 'active' : ''} onClick={() => toggleLang('pt')}>PT</button>
              <button className={lang === 'en' ? 'active' : ''} onClick={() => toggleLang('en')}>EN</button>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Workspace */}
      <div className="workspace">
        <header className="workspace-header">
          <div className="workspace-header-left">
            <h1>{headerTitle}</h1>
            <p>{headerSubtitle}</p>
          </div>
          <div className="actions">
            <button className="btn-secondary" onClick={() => void handleScanFolder()}>
              <IconFolder size={14} /> {t.btnScanFolder}
            </button>
            <button className="btn-primary" onClick={() => inputRef.current?.click()}>
              <IconUpload size={14} /> {t.btnSelectFile}
            </button>
          </div>
        </header>

        <div className="workspace-body">
          {noticeMsg && (
            <div className="notice ok-notice">
              <span>{noticeMsg}</span>
            </div>
          )}
          {error && (
            <div className="notice">
              <span>{error}</span>
            </div>
          )}

          {/* VIEW 1: PROTECTION CENTER */}
          {activeTab === 'guard' && (
            <ActiveGuardDashboard
              guard={guard}
              lang={lang}
              onToggleConfig={cfg => void handleToggleGuardConfig(cfg)}
              onScanFolder={() => void handleScanFolder()}
              onSelectFile={() => inputRef.current?.click()}
              onClearAlerts={() => void window.sentinelGuard?.clearAlerts().then(setGuard)}
              onOpenQuarantine={() => setActiveTab('quarantine')}
              onQuarantineFile={(fp, reason) => void handleQuarantineByPath(fp, reason)}
            />
          )}

          {/* VIEW 3: QUARANTINE VAULT */}
          {activeTab === 'quarantine' && (
            <QuarantineView
              guard={guard}
              lang={lang}
              onRestore={id => void handleRestoreQuarantine(id)}
              onDelete={id => void handleDeleteQuarantine(id)}
            />
          )}

          {/* VIEW 2: STATIC PE INSPECTOR */}
          {activeTab === 'scanner' && (
            <>
              {!analysis && !loading && (
                <div>
                  <div className="forensic-dropzone">
                    <div className="dropzone-icon">
                      <IconUpload size={22} />
                    </div>
                    <h2>{t.heroTitle1} — {t.heroTitle2}</h2>
                    <p>{t.heroLead}</p>
                    <div className="actions" style={{ justifyContent: 'center', marginBottom: 14 }}>
                      <button className="btn-primary" onClick={() => inputRef.current?.click()}>
                        <IconUpload size={14} /> {t.btnSelectFile}
                      </button>
                      <button className="btn-secondary" onClick={() => void handleScanFolder()}>
                        <IconFolder size={14} /> {t.btnScanFolder}
                      </button>
                    </div>
                    <small style={{ color: '#6e7681', fontSize: 11.5 }}>{t.dropHint}</small>
                  </div>

                  <div className="spec-grid">
                    <div className="spec-card">
                      <h4>{t.cardRansomware} & {t.cardInfostealer}</h4>
                      <p>{t.emptyReadySub}</p>
                    </div>
                    <div className="spec-card">
                      <h4>{t.findingsTitle}</h4>
                      <p>Classificação separada entre Capacidades de API, Indícios de Alta Especificidade e Contexto Estrutural PE.</p>
                    </div>
                    <div className="spec-card">
                      <h4>{t.ruleLabTitle}</h4>
                      <p>Geração determinística e auto-validação sintática de regras YARA e Sigma YAML prontas para SIEM/EDR.</p>
                    </div>
                  </div>
                </div>
              )}

              {loading && (
                <div className="forensic-dropzone">
                  <div className="spinner" />
                  <h2>{t.loadingTitle}</h2>
                  <p>{t.loadingSub}</p>
                </div>
              )}

              {analysis && !loading && (
                <div>
                  {/* Session History Bar */}
                  {history.length > 1 && (
                    <div className="history-bar">
                      <span>{t.sessionHistory}:</span>
                      {history.map(item => (
                        <button
                          key={item.sha256}
                          className={`ghost-sm ${item.sha256 === analysis.sha256 ? 'active' : ''}`}
                          onClick={() => setAnalysis(item)}
                        >
                          {item.fileName} ({item.riskScore})
                        </button>
                      ))}
                    </div>
                  )}

                  {/* Sample Command Header */}
                  <div className="sample-header-card">
                    <div className="sample-title-group">
                      <div className="sample-file-icon">
                        <IconScanner size={18} />
                      </div>
                      <div>
                        <h2>{analysis.fileName}</h2>
                        <p className="sample-meta-line">
                          {fmtBytes(analysis.fileSize)} · {analysis.architecture} · {analysis.subsystem} · SHA256: {analysis.sha256.slice(0, 16)}…
                        </p>
                      </div>
                    </div>

                    <div className="actions">
                      {analysis.filePath && window.sentinelGuard && (
                        <button className="ghost-sm danger-btn" onClick={() => void handleQuarantineCurrent()}>
                          {t.btnQuarantineCurrent}
                        </button>
                      )}
                      <button className="ghost-sm" onClick={() => downloadJsonReport(analysis)}>JSON</button>
                      <button className="ghost-sm" onClick={() => downloadText(`${analysis.fileName}.md`, markdownReport(analysis), 'text/markdown')}>Markdown</button>
                      <button className="ghost-sm" onClick={() => downloadText(`${analysis.fileName}.yara`, yaraRule(analysis) + yaraRuleBehavioral(analysis))}>YARA</button>
                      <button className="ghost-sm" onClick={() => downloadText(`${analysis.fileName}.sigma.yml`, sigmaRule(analysis), 'text/yaml')}>Sigma</button>
                      <button className="ghost-sm" onClick={() => window.print()}>{t.btnPrintPdf}</button>
                      <button className="ghost-sm" onClick={() => telemetryRef.current?.click()}>{t.btnImportTelemetry}</button>
                    </div>
                  </div>

                  {/* Executive Assessment Strip */}
                  <AssessmentStrip analysis={analysis} lang={lang} />

                  {/* Key Binary Metrics Strip */}
                  <div className="summary-subgrid">
                    <Metric label={t.labelEntryPoint} value={analysis.entryPoint} mono />
                    <Metric label={t.labelImageBase}  value={analysis.imageBase} mono />
                    <Metric label={t.labelSigned}     value={analysis.isAuthenticodeSigned ? t.certUnverified : t.no} />
                    <Metric label={t.labelTls}        value={analysis.hasTlsCallbacks ? t.yesWarn : t.noClean} />
                  </div>

                  {/* Forensic Sub-Tabs */}
                  <div className="subtabs-bar">
                    <button
                      className={`subtab-btn ${scannerSubTab === 'overview' ? 'active' : ''}`}
                      onClick={() => setScannerSubTab('overview')}
                    >
                      {t.subTabOverview} ({analysis.findings.length})
                    </button>
                    <button
                      className={`subtab-btn ${scannerSubTab === 'structure' ? 'active' : ''}`}
                      onClick={() => setScannerSubTab('structure')}
                    >
                      {t.subTabStructure} ({analysis.sections.length})
                    </button>
                    <button
                      className={`subtab-btn ${scannerSubTab === 'imports' ? 'active' : ''}`}
                      onClick={() => setScannerSubTab('imports')}
                    >
                      {t.subTabImports} ({analysis.importedFunctions.length})
                    </button>
                    <button
                      className={`subtab-btn ${scannerSubTab === 'strings' ? 'active' : ''}`}
                      onClick={() => setScannerSubTab('strings')}
                    >
                      {t.subTabStrings} ({analysis.strings.length + analysis.unicodeStrings.length})
                    </button>
                    <button
                      className={`subtab-btn ${scannerSubTab === 'rules' ? 'active' : ''}`}
                      onClick={() => setScannerSubTab('rules')}
                    >
                      {t.subTabRules}
                    </button>
                    <button
                      className={`subtab-btn ${scannerSubTab === 'all' ? 'active' : ''}`}
                      onClick={() => setScannerSubTab('all')}
                    >
                      {t.subTabAll}
                    </button>
                  </div>

                  {/* SUB-TAB 1: OVERVIEW (FINDINGS & HASHES) */}
                  {(scannerSubTab === 'overview' || scannerSubTab === 'all') && (
                    <>
                      <FindingsPanel findings={analysis.findings} lang={lang} />
                      <HashesPanel analysis={analysis} lang={lang} />
                    </>
                  )}

                  {/* SUB-TAB 2: PE STRUCTURE, SECTIONS, MITIGATIONS & EXTENDED METADATA */}
                  {(scannerSubTab === 'structure' || scannerSubTab === 'all') && (
                    <>
                      <div className="two-column">
                        <SectionsTable sections={analysis.sections} lang={lang} />
                        <MitigationsPanel
                          dllChars={analysis.dllCharacteristics}
                          isAuthenticodeSigned={analysis.isAuthenticodeSigned}
                          hasTls={analysis.hasTlsCallbacks}
                          lang={lang}
                        />
                      </div>

                      {(analysis.pdbPath || analysis.overlay || analysis.richHeaderHash || analysis.isDotNet || analysis.embeddedManifest?.executionLevel || analysis.hasDelayImports || analysis.apiSetImports.length > 0) && (
                        <article className="panel">
                          <div className="panel-title"><h3>{t.extraMetaTitle}</h3></div>
                          <div className="hash-grid">
                            {analysis.isDotNet && (
                              <div className="hash-row">
                                <span className="hash-label">.NET CLR</span>
                                <code className="hash-value">Managed Assembly (COM+ Runtime Header Present)</code>
                              </div>
                            )}
                            {analysis.embeddedManifest?.executionLevel && (
                              <div className="hash-row">
                                <span className="hash-label">Manifest UAC</span>
                                <code className="hash-value">{analysis.embeddedManifest.executionLevel}</code>
                              </div>
                            )}
                            {analysis.hasDelayImports && (
                              <div className="hash-row">
                                <span className="hash-label">Delay Imports</span>
                                <code className="hash-value">Present (Delay-Load Import Descriptor Active)</code>
                              </div>
                            )}
                            {analysis.apiSetImports.length > 0 && (
                              <div className="hash-row">
                                <span className="hash-label">API Sets</span>
                                <code className="hash-value">{analysis.apiSetImports.join(', ')}</code>
                              </div>
                            )}
                            {analysis.pdbPath && (
                              <div className="hash-row">
                                <span className="hash-label">PDB Path</span>
                                <code className="hash-value">{analysis.pdbPath}</code>
                                <CopyBtn value={analysis.pdbPath} />
                              </div>
                            )}
                            {analysis.richHeaderHash && (
                              <div className="hash-row">
                                <span className="hash-label">Rich Header MD5</span>
                                <code className="hash-value">{analysis.richHeaderHash}</code>
                                <CopyBtn value={analysis.richHeaderHash} />
                              </div>
                            )}
                            {analysis.overlay && (
                              <div className="hash-row">
                                <span className="hash-label">Overlay</span>
                                <code className="hash-value">
                                  {fmtBytes(analysis.overlay.size)} @ 0x{analysis.overlay.offset.toString(16).toUpperCase()}
                                </code>
                              </div>
                            )}
                          </div>
                        </article>
                      )}
                    </>
                  )}

                  {/* SUB-TAB 3: IMPORTS & EXPORTS */}
                  {(scannerSubTab === 'imports' || scannerSubTab === 'all') && (
                    <div className="two-column">
                      <ImportsPanel functions={analysis.importedFunctions} dlls={analysis.imports} lang={lang} />
                      <ExportsPanel exports={analysis.exports} lang={lang} />
                    </div>
                  )}

                  {/* SUB-TAB 4: STRINGS & IOCS */}
                  {(scannerSubTab === 'strings' || scannerSubTab === 'all') && (
                    <>
                      <IndicatorsPanel indicators={analysis.indicators} lang={lang} />
                      <StringsViewer ascii={analysis.strings} unicode={analysis.unicodeStrings} lang={lang} />
                    </>
                  )}

                  {/* SUB-TAB 5: YARA/SIGMA TEST LAB & TELEMETRY CORRELATION */}
                  {(scannerSubTab === 'rules' || scannerSubTab === 'all') && (
                    <>
                      <RuleTestLabPanel analysis={analysis} lang={lang} />

                      <article className="panel">
                        <div className="panel-title">
                          <h3>{t.telemetryTitle}</h3>
                          <div className="actions">
                            <span className="panel-count">{events.length}</span>
                            <button className="ghost-sm" onClick={() => telemetryRef.current?.click()}>
                              {t.btnImportTelemetry}
                            </button>
                          </div>
                        </div>
                        {events.length > 0 && (() => {
                          const chains = correlateTelemetryEvents(events)
                          return chains.length > 0 ? (
                            <div style={{ marginBottom: 14 }}>
                              <h4 style={{ margin: '0 0 8px', fontSize: 12.5, color: '#ffa657' }}>
                                {t.correlationTitle} ({chains.length})
                              </h4>
                              <ul className="findings-list">
                                {chains.map(c => (
                                  <li key={c.id}>
                                    <div className="finding-header">
                                      <b className={`severity ${c.severity}`}>{severityLabels[lang][c.severity]}</b>
                                      <span className={`finding-cat cat-${c.category}`}>{categoryLabels[lang][c.category]}</span>
                                      <span className="evidence-type ev-observed">{evidenceTypeLabels[lang].observed}</span>
                                      <strong className="finding-title">{c.title}</strong>
                                      <small className="mono" style={{ color: '#7d8590' }}>{c.process}</small>
                                    </div>
                                    <small className="finding-evidence">
                                      <div>{c.justification}</div>
                                      {c.steps.map((s, idx) => <div key={idx}>• [{s.stage}] {s.evidence}</div>)}
                                    </small>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          ) : (
                            <p className="muted" style={{ marginBottom: 10 }}>{t.correlationEmpty}</p>
                          )
                        })()}
                        {events.length ? (
                          <ol className="timeline">
                            {events.slice(0, 250).map((ev, i) => (
                              <li key={`${ev.timestamp}-${i}`}>
                                <time>{new Date(ev.timestamp).toLocaleString()}</time>
                                <div>
                                  <b>{ev.eventType}{ev.eventId ? ` (Event ID ${ev.eventId})` : ''}</b>
                                  <small>{ev.source}{ev.process ? ` · ${ev.process}` : ''}{ev.pid ? ` (PID ${ev.pid})` : ''}</small>
                                  <p>{ev.detail}</p>
                                </div>
                              </li>
                            ))}
                          </ol>
                        ) : (
                          <p className="muted">{t.telemetryEmpty}</p>
                        )}
                      </article>
                    </>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
