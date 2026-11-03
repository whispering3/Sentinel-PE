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

// ── Shared UI Components ──────────────────────────────────────────────────────

function CopyBtn({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    void copyToClipboard(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <button className="copy-btn" onClick={handleCopy} title="Copy">
      {copied ? '✓' : '⧉'}
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

function RiskGauge({
  score,
  confidence,
  decision,
  rationale,
  lang,
}: {
  score: number
  confidence: number
  decision: ResponseDecision
  rationale: string
  lang: Language
}) {
  const t = translations[lang]
  const color = score >= 80 ? '#ff4d6d' : score >= 50 ? '#ff9f43' : score >= 20 ? '#ffd700' : '#55e6a5'
  const label = score >= 80 ? t.riskCritical : score >= 50 ? t.riskHigh : score >= 20 ? t.riskMedium : t.riskLow
  const dash  = 220 - (score / 100) * 220
  const decColor = decision === 'block' ? '#ff4d6d' : decision === 'alert' ? '#ff9f43' : '#55e6a5'

  return (
    <article className="risk-gauge panel">
      <p className="panel-label">{t.riskScoreLabel}</p>
      <div className="gauge-wrap">
        <svg viewBox="0 0 100 55" className="gauge-svg">
          <path d="M10 50 A40 40 0 0 1 90 50" fill="none" stroke="#1a2d42" strokeWidth="8" strokeLinecap="round" />
          <path d="M10 50 A40 40 0 0 1 90 50" fill="none"
            stroke={color} strokeWidth="8" strokeLinecap="round"
            strokeDasharray="220" strokeDashoffset={`${dash}`}
            style={{ transition: 'stroke-dashoffset 0.8s ease, stroke 0.4s ease' }} />
          <text x="50" y="52" textAnchor="middle" fill={color} fontSize="18" fontWeight="800">{score}</text>
        </svg>
        <span className="gauge-label" style={{ color }}>{label}</span>
        <div className="confidence-pill">
          <span>{t.confidenceLabel}:</span>
          <strong>{confidence}%</strong>
        </div>
        <div className="decision-badge" style={{ borderColor: decColor, color: decColor }} title={rationale}>
          {decisionLabels[lang][decision]}
        </div>
      </div>
    </article>
  )
}

function ThreatOverviewCards({ findings, lang }: { findings: Finding[]; lang: Language }) {
  const t = translations[lang]
  const ransomwareHits = findings.filter(f => f.category === 'ransomware')
  const stealerHits    = findings.filter(f => f.category === 'infostealer')
  const injectionHits  = findings.filter(f => f.category === 'injection' || f.category === 'packer' || f.category === 'evasion')

  const cards = [
    {
      title: t.cardRansomware,
      icon: '🔒',
      hits: ransomwareHits,
    },
    {
      title: t.cardInfostealer,
      icon: '🍪',
      hits: stealerHits,
    },
    {
      title: t.cardInjection,
      icon: '💉',
      hits: injectionHits,
    },
  ]

  return (
    <div className="threat-cards-grid">
      {cards.map(({ title, icon, hits }) => {
        const hasCrit = hits.some(h => h.severity === 'critical' || h.severity === 'high')
        const hasAny  = hits.length > 0
        const cls     = hasCrit ? 'threat-card danger' : hasAny ? 'threat-card warn' : 'threat-card ok'
        return (
          <article key={title} className={cls}>
            <div className="threat-card-head">
              <span className="threat-icon">{icon}</span>
              <div>
                <h4>{title}</h4>
                <strong>{hasAny ? `${hits.length} — ${t.statusDetected}` : `✅ ${t.statusClean}`}</strong>
              </div>
            </div>
            {hasAny && (
              <ul className="threat-card-list">
                {hits.slice(0, 3).map((h, i) => (
                  <li key={i}>{translateRuleTitle(h.title, lang)}</li>
                ))}
              </ul>
            )}
          </article>
        )
      })}
    </div>
  )
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']
const SEV_COLOR: Record<Severity, string> = {
  critical: '#ff4d6d', high: '#ff9f43', medium: '#ffd700',
  low: '#7ad4f0', informational: '#a9b8ca',
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
        <h3>{t.findingsTitle}</h3>
        <span>{findings.length}</span>
      </div>

      {/* Severity + Category filters */}
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
  const [showPreview, setShowPreview] = useState<'none' | 'yara' | 'sigma'>('none')
  const fullYara = yaraRule(analysis) + yaraRuleBehavioral(analysis)
  const fullSigma = sigmaRule(analysis)

  return (
    <article className="panel">
      <div className="panel-title">
        <h3>🧪 {t.ruleLabTitle}</h3>
        <div className="actions">
          <button
            className={`ghost-sm ${showPreview === 'yara' ? 'active' : ''}`}
            onClick={() => setShowPreview(showPreview === 'yara' ? 'none' : 'yara')}
          >
            {showPreview === 'yara' ? '▾ YARA' : '▸ YARA'}
          </button>
          <button
            className={`ghost-sm ${showPreview === 'sigma' ? 'active' : ''}`}
            onClick={() => setShowPreview(showPreview === 'sigma' ? 'none' : 'sigma')}
          >
            {showPreview === 'sigma' ? '▾ Sigma' : '▸ Sigma'}
          </button>
        </div>
      </div>

      <div className="two-column" style={{ marginBottom: showPreview !== 'none' ? 12 : 0 }}>
        <div className={`metric ${validation.yaraValid && validation.matchesCurrentSample ? 'metric-ok' : 'metric-danger'}`}>
          <p>YARA ({validation.matchedStringsCount} matched strings)</p>
          <strong>{validation.yaraValid && validation.matchesCurrentSample ? t.ruleLabYaraOk : validation.warnings.join(', ')}</strong>
        </div>
        <div className={`metric ${validation.sigmaValid ? 'metric-ok' : 'metric-danger'}`}>
          <p>Sigma YAML (RFC-4122 UUID v4)</p>
          <strong>{validation.sigmaValid ? t.ruleLabSigmaOk : validation.warnings.join(', ')}</strong>
        </div>
      </div>

      {showPreview === 'yara' && (
        <pre className="rule-preview"><code>{fullYara}</code></pre>
      )}
      {showPreview === 'sigma' && (
        <pre className="rule-preview"><code>{fullSigma}</code></pre>
      )}
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
    <article className="panel hashes-panel">
      <div className="panel-title">
        <h3>{t.hashesTitle}</h3>
        <div className="actions">
          <a className="ghost-sm"
            href={`https://www.virustotal.com/gui/file/${analysis.sha256}`}
            target="_blank" rel="noreferrer noopener">
            🔎 VirusTotal
          </a>
          <a className="ghost-sm"
            href={`https://bazaar.abuse.ch/browse.php?search=sha256%3A${analysis.sha256}`}
            target="_blank" rel="noreferrer noopener">
            🔎 MalwareBazaar
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
        <h3>{t.sectionsTitle}</h3><span>{sections.length}</span>
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
                <td>{s.virtualSize.toLocaleString()}</td>
                <td>{s.rawSize.toLocaleString()}</td>
                <td className={s.entropy >= 7.5 ? 'text-danger' : s.entropy >= 7.2 ? 'text-warn' : ''}>
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
    <article className="panel imports-panel">
      <div className="panel-title">
        <h3>{t.importsTitle}</h3>
        <div className="actions">
          <span>{functions.length} {t.functionsCount} · {dlls.length} DLLs</span>
          <button className={`ghost ${view === 'dlls' ? 'active' : ''}`} onClick={() => setView('dlls')}>{t.btnDlls}</button>
          <button className={`ghost ${view === 'functions' ? 'active' : ''}`} onClick={() => setView('functions')}>{t.btnFunctions}</button>
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
                    <td>{f.ordinal !== undefined ? f.ordinal : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {functions.length > 500 && (
            <p className="muted" style={{ padding: '8px 0 0', fontSize: 12 }}>
              {t.showingTop} 500 {t.ofTotal} {functions.length}.
            </p>
          )}
        </>
      )}

      {view === 'dlls' && (
        <ul className="list">
          {dlls.map(dll => <li key={dll}>{dll}</li>)}
          {!dlls.length && <li>{t.noImports}</li>}
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
        <div className="panel-title"><h3>{t.exportsTitle}</h3><span>0</span></div>
        <p className="muted">{t.noExports}</p>
      </article>
    )
  }
  return (
    <article className="panel">
      <div className="panel-title"><h3>{t.exportsTitle}</h3><span>{exports.length}</span></div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Ordinal</th><th>API</th><th>RVA</th></tr></thead>
          <tbody>
            {exports.slice(0, 300).map((e, i) => (
              <tr key={i}>
                <td><code>{e.ordinal}</code></td>
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
          <span>{ascii.length} ASCII · {unicode.length} Unicode</span>
          <button className={`ghost ${tab === 'ascii' ? 'active' : ''}`} onClick={() => setTab('ascii')}>ASCII</button>
          <button className={`ghost ${tab === 'unicode' ? 'active' : ''}`} onClick={() => setTab('unicode')}>Unicode</button>
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
        <p className="muted" style={{ padding: '8px 0 0', fontSize: 12 }}>
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
      <div className="panel-title"><h3>{t.indicatorsTitle}</h3><span>{total}</span></div>
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
    { label: 'Certificate Table Present (not validated)', ok: isAuthenticodeSigned },
    { label: 'ASLR (DYNAMIC_BASE)', ok: dllChars.some(d => d.includes('DYNAMIC_BASE')) },
    { label: 'DEP / NX (NX_COMPAT)', ok: dllChars.some(d => d.includes('NX_COMPAT')) },
    { label: 'Control Flow Guard (CFG)', ok: dllChars.some(d => d.includes('GUARD_CF')) },
    { label: 'High Entropy VA (64-bit ASLR)', ok: dllChars.some(d => d.includes('HIGH_ENTROPY_VA')) },
    { label: 'No SEH', ok: dllChars.some(d => d.includes('NO_SEH')) },
    { label: 'No TLS Callbacks', ok: !hasTls },
  ]

  return (
    <article className="panel">
      <div className="panel-title"><h3>{t.mitigationsTitle}</h3></div>
      <ul className="mitigations-list">
        {checks.map(({ label, ok }) => (
          <li key={label} className={ok ? 'mit-ok' : 'mit-missing'}>
            <span>{ok ? '✅' : '❌'}</span> {label}
          </li>
        ))}
      </ul>
    </article>
  )
}

// ── Active Guard Dashboard Component ──────────────────────────────────────────
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

  return (
    <section className="results">
      <div className="result-heading">
        <div>
          <p className="eyebrow">{t.eyebrow}</p>
          <h2>🛡️ {t.guardTitle}</h2>
          <p style={{ margin: '6px 0 0', color: '#8ba4bf', fontSize: 14 }}>{t.guardSubtitle}</p>
        </div>
        <div className="actions">
          <button className="ghost" onClick={onScanFolder}>{t.btnScanFolder}</button>
          <button className="primary" onClick={onSelectFile}>{t.btnSelectFile}</button>
        </div>
      </div>

      {/* Status Metrics */}
      <div className="summary-subgrid" style={{ marginBottom: 14 }}>
        <Metric
          label={t.metricShield}
          value={guard.enabled ? `🟢 ${t.metricShieldOn}` : `⚪ ${t.metricShieldOff}`}
          highlight={guard.enabled ? 'ok' : undefined}
        />
        <Metric
          label={t.metricCanary}
          value={
            guard.canaryStatus === 'tampered'
              ? t.metricCanaryTampered
              : guard.canaryStatus === 'intact'
                ? `🟢 ${t.metricCanaryIntact}`
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

      {/* Control switches (Opt-In) */}
      <article className="panel guard-controls">
        <label className="switch-row">
          <input
            type="checkbox"
            checked={guard.enabled}
            onChange={e => onToggleConfig({ enabled: e.target.checked })}
          />
          <span><strong>{t.guardRealtimeToggle}</strong></span>
        </label>
        <label className="switch-row">
          <input
            type="checkbox"
            checked={guard.canaryEnabled}
            onChange={e => onToggleConfig({ canaryEnabled: e.target.checked })}
          />
          <span><strong>{t.guardCanaryToggle}</strong></span>
        </label>
        <span style={{ fontSize: 12, color: '#55e6a5', marginLeft: 'auto' }}>
          🔒 {t.guardAutoBlockToggle}
        </span>
      </article>

      {/* Live Alerts Feed */}
      <article className="panel">
        <div className="panel-title">
          <h3>🚨 {t.alertsTitle}</h3>
          <div className="actions">
            <span>{guard.alerts.length}</span>
            {guard.quarantine.length > 0 && (
              <button className="ghost-sm" onClick={onOpenQuarantine}>
                🔒 {t.navQuarantine} ({guard.quarantine.length})
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
              <li key={a.id} className="alert-item">
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
                  <time style={{ fontSize: 12, color: '#758da5' }}>
                    {new Date(a.timestamp).toLocaleTimeString()}
                  </time>
                </div>
                <small className="finding-evidence">
                  <div><b>File:</b> {a.filePath} (Score: {a.riskScore}/100)</div>
                  {a.details.map((d, idx) => <div key={idx}>• {d}</div>)}
                </small>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">{t.noAlerts}</p>
        )}
      </article>

      {/* Suspicious Process Monitor */}
      <article className="panel">
        <div className="panel-title">
          <h3>⚡ {t.processesTitle}</h3>
          <div className="actions">
            <span>{processes.length}</span>
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
                    <td style={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis' }} title={p.commandLine}>
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
          <p className="muted">✅ {t.noSuspiciousProcesses}</p>
        )}
      </article>

      {/* Monitored Folders & Canary Files */}
      <div className="two-column">
        <article className="panel">
          <div className="panel-title">
            <h3>📂 {t.watchedFoldersTitle}</h3>
            <span>{guard.watchedFolders.length}</span>
          </div>
          <ul className="list">
            {guard.watchedFolders.map(f => <li key={f}>🟢 {f}</li>)}
            {guard.watchedFolders.length === 0 && <li className="muted">{t.metricShieldOff}</li>}
          </ul>
        </article>

        <article className="panel">
          <div className="panel-title">
            <h3>🪤 {t.canaryFilesTitle}</h3>
            <span>{guard.canaryFiles.length}</span>
          </div>
          <ul className="list">
            {guard.canaryFiles.map(f => <li key={f}>🛡️ {f}</li>)}
            {guard.canaryFiles.length === 0 && <li className="muted">{t.metricCanaryOff}</li>}
          </ul>
        </article>
      </div>
    </section>
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
    <section className="results">
      <div className="result-heading">
        <div>
          <p className="eyebrow">{t.eyebrow}</p>
          <h2>🔒 {t.quarantineTitle}</h2>
          <p style={{ margin: '6px 0 0', color: '#8ba4bf', fontSize: 14 }}>{t.quarantineSubtitle}</p>
        </div>
      </div>

      <article className="panel">
        <div className="panel-title">
          <h3>{t.quarantineTitle}</h3>
          <span>{guard.quarantine.length}</span>
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
                    <td>{new Date(item.quarantinedAt).toLocaleString()}</td>
                    <td>
                      <strong>{item.fileName}</strong>
                      <small style={{ display: 'block', color: '#6a7f96' }}>{item.originalPath}</small>
                    </td>
                    <td>
                      <span className={`finding-cat cat-${item.category}`}>
                        {categoryLabels[lang][item.category]}
                      </span>
                    </td>
                    <td><strong className="text-danger">{item.riskScore}/100</strong></td>
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
    </section>
  )
}

// ── Main Application ──────────────────────────────────────────────────────────
export default function App() {
  const inputRef     = useRef<HTMLInputElement>(null)
  const telemetryRef = useRef<HTMLInputElement>(null)

  const [lang, setLang] = useState<Language>(() => {
    const saved = localStorage.getItem('sentinel_lang')
    return saved === 'en' || saved === 'pt' ? saved : 'pt'
  })
  const [activeTab, setActiveTab] = useState<'guard' | 'scanner' | 'quarantine'>('guard')

  const [guard, setGuard]       = useState<GuardStatus>(DEFAULT_GUARD_STATUS)
  const [analysis, setAnalysis] = useState<PeAnalysis>()
  const [history, setHistory]   = useState<PeAnalysis[]>([])
  const [events, setEvents]     = useState<TelemetryEvent[]>([])
  const [error, setError]       = useState<string>()
  const [loading, setLoading]   = useState(false)
  const [dragging, setDragging] = useState(false)
  const [noticeMsg, setNoticeMsg] = useState<string>()

  const t = translations[lang]

  const toggleLang = (next: Language) => {
    setLang(next)
    localStorage.setItem('sentinel_lang', next)
  }

  // Subscribe to Electron Real-Time Guard IPC
  useEffect(() => {
    if (!window.sentinelGuard) return
    void window.sentinelGuard.getStatus().then(setGuard)
    const unsub = window.sentinelGuard.onStatusUpdate(setGuard)
    return unsub
  }, [])

  const inspect = async (file?: File | null) => {
    if (!file) return
    setActiveTab('scanner')
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
          ? `Arquivo movido com segurança para o Cofre de Quarentena!`
          : `File safely moved to the Quarantine Vault!`
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
      `Manual quarantine from Static Analyzer (Score ${analysis.riskScore}/100)`
    )
  }

  const handleRestoreQuarantine = async (id: string) => {
    if (!window.sentinelGuard) return
    setError(undefined)
    const res = await window.sentinelGuard.restoreQuarantine(id)
    if (res.ok) {
      setNoticeMsg(
        lang === 'pt'
          ? 'Arquivo restaurado com sucesso para o caminho original!'
          : 'File successfully restored to its original path!'
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
          ? 'Arquivo excluído permanentemente do cofre.'
          : 'File permanently deleted from quarantine.'
      )
      setTimeout(() => setNoticeMsg(undefined), 5000)
    } else if (res.error && !res.error.toLowerCase().includes('cancel')) {
      setError(res.error)
    }
  }

  // Drag & drop anywhere
  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setDragging(true)
  }, [])
  const onDragLeave = useCallback(() => setDragging(false), [])
  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setDragging(false)
    void inspect(e.dataTransfer.files?.[0])
  }, [])

  return (
    <main
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
      className={dragging ? 'drag-over' : ''}
    >
      {dragging && <div className="drop-overlay"><span>{t.dropOverlay}</span></div>}

      {/* Top Bar */}
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">S</span>
          <span>Sentinel <b>PE</b></span>
        </div>

        <nav className="nav-tabs">
          <button
            className={`nav-tab ${activeTab === 'guard' ? 'active' : ''}`}
            onClick={() => setActiveTab('guard')}
          >
            🛡️ {t.navGuard}
            {guard.alerts.length > 0 && <span className="nav-badge danger">{guard.alerts.length}</span>}
          </button>
          <button
            className={`nav-tab ${activeTab === 'scanner' ? 'active' : ''}`}
            onClick={() => setActiveTab('scanner')}
          >
            🔬 {t.navScanner}
          </button>
          <button
            className={`nav-tab ${activeTab === 'quarantine' ? 'active' : ''}`}
            onClick={() => setActiveTab('quarantine')}
          >
            🔒 {t.navQuarantine}
            {guard.quarantine.length > 0 && <span className="nav-badge">{guard.quarantine.length}</span>}
          </button>
        </nav>

        <div className="topbar-right">
          <span className="status">
            <i className={guard.enabled ? '' : 'paused'} />
            {guard.enabled ? t.statusActive : t.statusPaused}
          </span>
          <div className="lang-switch">
            <button className={lang === 'pt' ? 'active' : ''} onClick={() => toggleLang('pt')}>PT</button>
            <button className={lang === 'en' ? 'active' : ''} onClick={() => toggleLang('en')}>EN</button>
          </div>
        </div>
      </header>

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

      {noticeMsg && (
        <section className="notice ok-notice" style={{ maxWidth: 1180, margin: '12px auto' }}>
          {noticeMsg}
        </section>
      )}
      {error && (
        <section className="notice error" style={{ maxWidth: 1180, margin: '12px auto' }}>
          {error}
        </section>
      )}

      {/* TAB 1: ACTIVE GUARD */}
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

      {/* TAB 3: QUARANTINE VAULT */}
      {activeTab === 'quarantine' && (
        <QuarantineView
          guard={guard}
          lang={lang}
          onRestore={id => void handleRestoreQuarantine(id)}
          onDelete={id => void handleDeleteQuarantine(id)}
        />
      )}

      {/* TAB 2: STATIC ANALYZER */}
      {activeTab === 'scanner' && (
        <>
          {!analysis && !loading && (
            <>
              <section className="hero">
                <p className="eyebrow">{t.eyebrow}</p>
                <h1>{t.heroTitle1}<br /><em>{t.heroTitle2}</em></h1>
                <p className="lead">{t.heroLead}</p>
                <div className="actions" style={{ justifyContent: 'center' }}>
                  <button className="primary" onClick={() => inputRef.current?.click()}>
                    {t.btnSelectFile}
                  </button>
                  <button className="ghost" onClick={() => void handleScanFolder()}>
                    {t.btnScanFolder}
                  </button>
                </div>
                <p style={{ fontSize: 12, color: '#6a7f96', marginTop: 12 }}>{t.dropHint}</p>
                <p className="privacy">{t.privacyNote}</p>
              </section>

              <section className="empty">
                <div>01</div>
                <h2>{t.emptyReadyTitle}</h2>
                <p>{t.emptyReadySub}</p>
              </section>
            </>
          )}

          {loading && (
            <section className="empty">
              <div className="spinner" />
              <h2>{t.loadingTitle}</h2>
              <p>{t.loadingSub}</p>
            </section>
          )}

          {analysis && !loading && (
            <section className="results">
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

              {/* Heading & Export Actions */}
              <div className="result-heading">
                <div>
                  <p className="eyebrow">{t.sampleAnalyzed}</p>
                  <h2>{analysis.fileName}</h2>
                  <p style={{ margin: '4px 0 0', color: '#6a7f96', fontSize: 13 }}>
                    {fmtBytes(analysis.fileSize)} · {analysis.architecture} · {analysis.subsystem}
                  </p>
                </div>
                <div className="actions flex-wrap">
                  {analysis.filePath && window.sentinelGuard && (
                    <button className="ghost danger-btn" onClick={() => void handleQuarantineCurrent()}>
                      {t.btnQuarantineCurrent}
                    </button>
                  )}
                  <button className="ghost" onClick={() => downloadJsonReport(analysis)}>JSON</button>
                  <button className="ghost" onClick={() => downloadText(`${analysis.fileName}.md`, markdownReport(analysis), 'text/markdown')}>Markdown</button>
                  <button className="ghost" onClick={() => downloadText(`${analysis.fileName}.yara`, yaraRule(analysis) + yaraRuleBehavioral(analysis))}>YARA</button>
                  <button className="ghost" onClick={() => downloadText(`${analysis.fileName}.sigma.yml`, sigmaRule(analysis), 'text/yaml')}>Sigma</button>
                  <button className="ghost" onClick={() => window.print()}>{t.btnPrintPdf}</button>
                  <button className="ghost" onClick={() => telemetryRef.current?.click()}>{t.btnImportTelemetry}</button>
                  <button className="primary" onClick={() => inputRef.current?.click()}>{t.btnNewAnalysis}</button>
                </div>
              </div>

              {/* Executive Threat Summary Cards (Ransomware / Infostealer / Injection) */}
              <ThreatOverviewCards findings={analysis.findings} lang={lang} />

              {/* Score + Summary Grid */}
              <div className="top-grid">
                <RiskGauge
                  score={analysis.riskScore}
                  confidence={analysis.confidenceScore}
                  decision={analysis.recommendedDecision}
                  rationale={analysis.decisionRationale}
                  lang={lang}
                />
                <div className="summary-subgrid">
                  <Metric label={t.labelArch}       value={analysis.architecture} />
                  <Metric label={t.labelSubsystem}  value={analysis.subsystem} />
                  <Metric label={t.labelEntryPoint} value={analysis.entryPoint} mono />
                  <Metric label={t.labelImageBase}  value={analysis.imageBase} mono />
                  <Metric label={t.labelTimestamp}  value={new Date(analysis.timestamp).toLocaleDateString()} />
                  <Metric label={t.labelSigned}     value={analysis.isAuthenticodeSigned ? t.certUnverified : t.no} />
                  <Metric label={t.labelTls}        value={analysis.hasTlsCallbacks ? t.yesWarn : t.noClean} />
                  <Metric label={t.labelSize}       value={fmtBytes(analysis.fileSize)} />
                </div>
              </div>

              {/* Explainable Decision Rationale Banner */}
              <article className="panel rationale-banner">
                <strong>{t.decisionLabel}: {decisionLabels[lang][analysis.recommendedDecision]} ({t.confidenceLabel}: {analysis.confidenceScore}%)</strong>
                <p style={{ margin: '4px 0 0', fontSize: 13, color: '#a9b8cb' }}>{analysis.decisionRationale}</p>
              </article>

              {/* Hashes & Hash Comparator */}
              <HashesPanel analysis={analysis} lang={lang} />

              {/* Findings */}
              <FindingsPanel findings={analysis.findings} lang={lang} />

              {/* Rule Test Lab */}
              <RuleTestLabPanel analysis={analysis} lang={lang} />

              {/* Sections + Mitigations */}
              <div className="two-column">
                <SectionsTable sections={analysis.sections} lang={lang} />
                <MitigationsPanel
                  dllChars={analysis.dllCharacteristics}
                  isAuthenticodeSigned={analysis.isAuthenticodeSigned}
                  hasTls={analysis.hasTlsCallbacks}
                  lang={lang}
                />
              </div>

              {/* Imports + Exports */}
              <div className="two-column">
                <ImportsPanel functions={analysis.importedFunctions} dlls={analysis.imports} lang={lang} />
                <ExportsPanel exports={analysis.exports} lang={lang} />
              </div>

              {/* Indicators */}
              <IndicatorsPanel indicators={analysis.indicators} lang={lang} />

              {/* Strings */}
              <StringsViewer ascii={analysis.strings} unicode={analysis.unicodeStrings} lang={lang} />

              {/* External Telemetry & Behavioral Correlation Engine */}
              <article className="panel telemetry">
                <div className="panel-title"><h3>{t.telemetryTitle}</h3><span>{events.length}</span></div>
                {events.length > 0 && (() => {
                  const chains = correlateTelemetryEvents(events)
                  return chains.length > 0 ? (
                    <div style={{ marginBottom: 16 }}>
                      <h4 style={{ margin: '0 0 8px', fontSize: 13, color: '#ff9f43' }}>🔗 {t.correlationTitle} ({chains.length})</h4>
                      <ul className="findings-list">
                        {chains.map(c => (
                          <li key={c.id}>
                            <div className="finding-header">
                              <b className={`severity ${c.severity}`}>{severityLabels[lang][c.severity]}</b>
                              <span className={`finding-cat cat-${c.category}`}>{categoryLabels[lang][c.category]}</span>
                              <span className="evidence-type ev-observed">{evidenceTypeLabels[lang].observed}</span>
                              <strong className="finding-title">{c.title}</strong>
                              <small style={{ color: '#8ba4bf' }}>{c.process}</small>
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
                    <p className="muted" style={{ fontSize: 12, marginBottom: 12 }}>{t.correlationEmpty}</p>
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

              {/* Compiler, .NET CLR, Delay-Imports, Manifest & Overlay Metadata */}
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
            </section>
          )}
        </>
      )}
    </main>
  )
}
