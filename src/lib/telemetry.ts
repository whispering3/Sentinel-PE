import type { CorrelatedChain, TelemetryEvent } from '../types'

const MAX_TELEMETRY_BYTES = 10 * 1024 * 1024
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
const text = (value: unknown, fallback = '') =>
  typeof value === 'string' ? value.trim() : typeof value === 'number' ? String(value) : fallback

export async function importTelemetry(file: File): Promise<TelemetryEvent[]> {
  if (file.size > MAX_TELEMETRY_BYTES) throw new Error('A evidência excede o limite de 10 MB.')
  let parsed: unknown
  try {
    parsed = JSON.parse(await file.text())
  } catch {
    throw new Error('Use um arquivo JSON de evidências válido.')
  }
  const values = Array.isArray(parsed)
    ? parsed
    : isRecord(parsed) && Array.isArray(parsed.events)
      ? parsed.events
      : undefined
  if (!values) throw new Error('O JSON deve conter um array ou a propriedade events.')

  const events = values.flatMap((value): TelemetryEvent[] => {
    if (!isRecord(value)) return []
    const timestamp = text(value.timestamp) || text(value.time) || text(value.utcTime)
    const source = text(value.source) || text(value.provider) || 'Sysmon / Evidência'
    const rawEventId = Number(value.eventId ?? value.event_id ?? value.EventID)
    const eventId = Number.isFinite(rawEventId) && rawEventId > 0 ? rawEventId : undefined
    const eventType =
      text(value.eventType) ||
      (eventId ? `Sysmon Event ${eventId}` : '') ||
      text(value.event) ||
      'Evento'
    const detail =
      text(value.detail) ||
      text(value.message) ||
      text(value.commandLine) ||
      text(value.targetFilename) ||
      text(value.targetObject) ||
      JSON.stringify(value).slice(0, 800)
    if (!timestamp || Number.isNaN(Date.parse(timestamp))) return []
    const rawPid = Number(value.pid ?? value.processId ?? value.ProcessId)
    return [
      {
        timestamp,
        source,
        eventType,
        eventId,
        process: text(value.process) || text(value.image) || text(value.Image),
        parentProcess: text(value.parentProcess) || text(value.parentImage) || text(value.ParentImage),
        pid: Number.isFinite(rawPid) && rawPid > 0 ? rawPid : undefined,
        detail,
        confidence: 'observed',
      },
    ]
  })
  if (!events.length) throw new Error('Nenhum evento com timestamp válido foi encontrado.')
  return events
    .sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp))
    .slice(0, 5000)
}

/**
 * Behavioral Correlation Engine:
 * Groups observed telemetry events by process identity and detects multi-stage
 * attack sequences (Infostealer exfiltration, Ransomware sabotage, Process Injection).
 */
export function correlateTelemetryEvents(events: TelemetryEvent[]): CorrelatedChain[] {
  if (!events.length) return []

  const byProcess = new Map<string, TelemetryEvent[]>()
  for (const ev of events) {
    const key = (ev.process || 'unknown_process').toLowerCase()
    const list = byProcess.get(key) ?? []
    list.push(ev)
    byProcess.set(key, list)
  }

  const chains: CorrelatedChain[] = []

  for (const [procKey, procEvents] of byProcess.entries()) {
    const displayProc = procEvents[0]?.process || procKey

    // 1. Check for Infostealer Sequence: Writable Dir Execution + Credential/Cookie Access + Network
    const writableExec = procEvents.find(e =>
      /appdata\\local\\temp|appdata\\roaming|\\downloads\\|\\users\\public\\/i.test(
        `${e.process ?? ''} ${e.detail}`,
      ),
    )
    const credAccess = procEvents.find(e =>
      /login data|network\\cookies|local state|cookies\.sqlite|leveldb|tdata|lsass\.exe|sam|cryptunprotectdata/i.test(
        e.detail,
      ) || e.eventId === 10,
    )
    const netConnect = procEvents.find(
      e =>
        e.eventId === 3 ||
        e.eventId === 22 ||
        /network|connect|http|https|dns|socket|\b(?:\d{1,3}\.){3}\d{1,3}\b/i.test(
          `${e.eventType} ${e.detail}`,
        ),
    )

    if (credAccess && (writableExec || netConnect)) {
      const steps: CorrelatedChain['steps'] = []
      if (writableExec) {
        steps.push({
          timestamp: writableExec.timestamp,
          stage: 'Execução em diretório gravável',
          evidence: writableExec.detail,
        })
      }
      steps.push({
        timestamp: credAccess.timestamp,
        stage: 'Acesso a credenciais / cookies / LSASS',
        evidence: credAccess.detail,
      })
      if (netConnect) {
        steps.push({
          timestamp: netConnect.timestamp,
          stage: 'Comunicação externa / Exfiltração',
          evidence: netConnect.detail,
        })
      }

      chains.push({
        id: `chain-stealer-${procKey}`,
        severity: writableExec && netConnect ? 'critical' : 'high',
        category: 'infostealer',
        title: 'Cadeia Comportamental Correlacionada: Possível Infostealer',
        process: displayProc,
        steps,
        justification:
          'Correlação de múltiplos eventos observados para o mesmo processo (acesso a repositório de sessão/credenciais combinado com execução em pasta temporária ou conexão de rede).',
      })
    }

    // 2. Check for Ransomware Sequence: Recovery Sabotage + Rapid File Modification
    const recoveryTamper = procEvents.find(e =>
      /vssadmin.*delete|wmic.*shadowcopy|bcdedit.*recoveryenabled|wbadmin.*delete/i.test(e.detail),
    )
    const fileMods = procEvents.filter(
      e =>
        e.eventId === 11 ||
        /file create|file modified|rename|\.locked|\.encrypted|\.crypt/i.test(
          `${e.eventType} ${e.detail}`,
        ),
    )

    if (recoveryTamper || fileMods.length >= 3) {
      const steps: CorrelatedChain['steps'] = []
      if (recoveryTamper) {
        steps.push({
          timestamp: recoveryTamper.timestamp,
          stage: 'Sabotagem de recuperação (Shadow Copy / Boot)',
          evidence: recoveryTamper.detail,
        })
      }
      if (fileMods.length > 0) {
        steps.push({
          timestamp: fileMods[0].timestamp,
          stage: `Modificação em massa de arquivos (${fileMods.length} eventos)`,
          evidence: fileMods.slice(0, 2).map(m => m.detail).join(' | '),
        })
      }

      if (steps.length > 0 && (recoveryTamper || fileMods.length >= 4)) {
        chains.push({
          id: `chain-ransom-${procKey}`,
          severity: recoveryTamper ? 'critical' : 'high',
          category: 'ransomware',
          title: 'Cadeia Comportamental Correlacionada: Atividade de Ransomware',
          process: displayProc,
          steps,
          justification:
            'Processo executou comandos de destruição de cópias de sombra/recuperação e/ou alterações rápidas em múltiplos arquivos.',
        })
      }
    }

    // 3. Check for Process Injection + Persistence (Sysmon Event 8 + 12/13)
    const remoteThread = procEvents.find(
      e => e.eventId === 8 || /createremotethread|virtualallocex|process hollowing/i.test(`${e.eventType} ${e.detail}`),
    )
    const regPersist = procEvents.find(
      e =>
        e.eventId === 12 ||
        e.eventId === 13 ||
        e.eventId === 14 ||
        /currentversion\\run|winlogon|schtasks|createservice/i.test(e.detail),
    )

    if (remoteThread && regPersist) {
      chains.push({
        id: `chain-inject-${procKey}`,
        severity: 'high',
        category: 'injection',
        title: 'Cadeia Comportamental Correlacionada: Injeção + Persistência',
        process: displayProc,
        steps: [
          {
            timestamp: remoteThread.timestamp,
            stage: 'Injeção em processo remoto (Event 8)',
            evidence: remoteThread.detail,
          },
          {
            timestamp: regPersist.timestamp,
            stage: 'Persistência em Registro / Serviço (Event 12-14)',
            evidence: regPersist.detail,
          },
        ],
        justification:
          'O mesmo processo realizou injeção de thread remota e alterou chaves de inicialização/persistência.',
      })
    }
  }

  return chains
}
