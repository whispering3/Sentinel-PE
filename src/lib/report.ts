import type { PeAnalysis } from '../types'

const SENTINEL_VERSION = '0.3.0'
const RULE_ENGINE_VERSION = '2.1.0-explainable'

export const downloadJsonReport = (analysis: PeAnalysis) => {
  const body = JSON.stringify(
    {
      chainOfCustody: {
        generatedAtUtc: new Date().toISOString(),
        tool: 'Sentinel PE',
        toolVersion: SENTINEL_VERSION,
        ruleEngineVersion: RULE_ENGINE_VERSION,
        analysisMode: 'local-static-non-execution',
        evidenceHashes: {
          sha256: analysis.sha256,
          sha1: analysis.sha1,
          md5: analysis.md5,
          impHash: analysis.impHash || null,
        },
        decisionSummary: {
          riskScore: analysis.riskScore,
          confidenceScore: analysis.confidenceScore,
          recommendedDecision: analysis.recommendedDecision,
          decisionRationale: analysis.decisionRationale,
        },
      },
      analysis,
    },
    null,
    2,
  )
  const url = URL.createObjectURL(new Blob([body], { type: 'application/json' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `${analysis.fileName}.sentinel.json`
  a.click()
  URL.revokeObjectURL(url)
}

const riskLabel = (score: number) =>
  score >= 80 ? '🔴 CRÍTICO' :
  score >= 50 ? '🟠 ALTO' :
  score >= 20 ? '🟡 ATENÇÃO' : '🟢 BAIXO'

const decisionLabel = (d: PeAnalysis['recommendedDecision']) =>
  d === 'block' ? '🛑 ISOLAR / QUARENTENAR (Evidências Fortes)' :
  d === 'alert' ? '⚠️ REVISÃO MANUAL RECOMENDADA' :
  '👁️ OBSERVAR (Baixo Risco)'

export const markdownReport = (a: PeAnalysis): string => {
  const sectionTable = a.sections
    .map(
      s =>
        `| ${s.name || '—'} | ${s.virtualAddress} | ${s.virtualSize.toLocaleString()} | ${s.rawSize.toLocaleString()} | ${s.entropy.toFixed(3)} | ${s.flags.join(', ')} |`,
    )
    .join('\n')

  const findingsList = a.findings
    .map(
      f =>
        `- **[${f.severity.toUpperCase()} | ${f.evidenceType.toUpperCase()}]** [${f.category}] ${f.title}\n  - ${f.evidence}`,
    )
    .join('\n')

  const hashTable = [
    `| SHA-256  | \`${a.sha256}\` |`,
    `| SHA-1    | \`${a.sha1}\` |`,
    `| MD5      | \`${a.md5}\` |`,
    a.impHash ? `| ImpHash  | \`${a.impHash}\` |` : '',
  ]
    .filter(Boolean)
    .join('\n')

  return `# Sentinel PE — Relatório de Triagem Explicável & Cadeia de Custódia

## Cadeia de Custódia (Chain of Custody)

- **Arquivo Analisado:** \`${a.fileName}\`
- **Data/Hora (UTC):** ${new Date().toISOString()}
- **Versão do Sentinel PE:** v${SENTINEL_VERSION} (Motor de Regras v${RULE_ENGINE_VERSION})
- **Score de Risco:** ${a.riskScore}/100 — ${riskLabel(a.riskScore)}
- **Confiança da Detecção:** ${a.confidenceScore}%
- **Decisão Recomendada:** ${decisionLabel(a.recommendedDecision)}
- **Justificativa:** ${a.decisionRationale}

---

## Hashes da Evidência

| Tipo | Valor |
|------|-------|
${hashTable}

## Metadados PE

| Campo | Valor |
|-------|-------|
| Arquitetura | ${a.architecture} |
| Subsystem | ${a.subsystem} |
| Entry Point | \`${a.entryPoint}\` |
| Image Base | \`${a.imageBase}\` |
| Timestamp | ${a.timestamp} |
| Authenticode | ${a.isAuthenticodeSigned ? '⚠️ Tabela presente (requer validação WinVerifyTrust)' : '❌ Não assinado'} |
| .NET / CLR | ${a.isDotNet ? 'Sim (Managed Assembly)' : 'Não'} |
| Delay Imports | ${a.hasDelayImports ? 'Sim' : 'Não'} |
| TLS Callbacks | ${a.hasTlsCallbacks ? '⚠️ Sim' : 'Não'} |
${a.embeddedManifest?.executionLevel ? `| Nível de Execução (Manifesto) | \`${a.embeddedManifest.executionLevel}\` |` : ''}
${a.pdbPath ? `| PDB Path | \`${a.pdbPath}\` |` : ''}
${a.overlay ? `| Overlay | ${(a.overlay.size / 1024).toFixed(1)} KB @ 0x${a.overlay.offset.toString(16).toUpperCase()} |` : ''}

## Mitigações

${a.dllCharacteristics.length ? a.dllCharacteristics.map(d => `- ✅ ${d}`).join('\n') : '- ❌ Nenhuma mitigação de binário detectada'}

## Seções

| Nome | RVA | Virtual | Raw | Entropia | Flags |
|------|-----|---------|-----|----------|-------|
${sectionTable}

## Evidências Classificadas (Capacidade / Indício / Contexto)

${findingsList || '*Nenhum achado registrado.*'}

---

> ⚠️ **Nota Metodológica:** Indicadores estáticos distinguem **Capacidades** (APIs importadas), **Indícios** (strings/estruturas suspeitas) e **Contexto** (ausência de mitigações). A confirmação definitiva de comprometimento requer correlação com telemetria comportamental observada.
`
}
