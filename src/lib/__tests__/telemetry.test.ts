import { describe, expect, it } from 'vitest'
import { correlateTelemetryEvents, importTelemetry } from '../telemetry'
import type { TelemetryEvent } from '../../types'

describe('telemetry importer and behavioral correlation engine', () => {
  it('parses valid Sysmon and sandbox telemetry events and sorts chronologically', async () => {
    const rawEvents = [
      {
        timestamp: '2026-11-03T15:02:00Z',
        source: 'Sysmon',
        eventType: 'NetworkConnect',
        eventId: 3,
        process: 'C:\\Users\\User\\AppData\\Local\\Temp\\stealer.exe',
        pid: 4412,
        detail: 'Outbound connection to 198.51.100.42:443',
      },
      {
        timestamp: '2026-11-03T15:00:00Z',
        source: 'Sysmon',
        eventType: 'ProcessCreate',
        eventId: 1,
        process: 'C:\\Users\\User\\AppData\\Local\\Temp\\stealer.exe',
        pid: 4412,
        detail: 'Launched from writable AppData\\Local\\Temp directory',
      },
    ]

    const file = new File([JSON.stringify(rawEvents)], 'telemetry.json', {
      type: 'application/json',
    })
    const events = await importTelemetry(file)
    expect(events).toHaveLength(2)
    expect(events[0].eventId).toBe(1)
    expect(events[1].eventId).toBe(3)
  })

  it('correlates multi-stage Infostealer chain (writable path + browser cookie access + network)', () => {
    const events: TelemetryEvent[] = [
      {
        timestamp: '2026-11-03T15:00:00Z',
        source: 'Sysmon',
        eventType: 'ProcessCreate',
        eventId: 1,
        process: 'C:\\Users\\Admin\\AppData\\Local\\Temp\\drop.exe',
        pid: 5100,
        detail: 'Process started in AppData\\Local\\Temp\\drop.exe',
        confidence: 'observed',
      },
      {
        timestamp: '2026-11-03T15:00:02Z',
        source: 'Sysmon',
        eventType: 'FileAccess',
        eventId: 11,
        process: 'C:\\Users\\Admin\\AppData\\Local\\Temp\\drop.exe',
        pid: 5100,
        detail: 'Accessed Google\\Chrome\\User Data\\Default\\Network\\Cookies and Login Data',
        confidence: 'observed',
      },
      {
        timestamp: '2026-11-03T15:00:05Z',
        source: 'Sysmon',
        eventType: 'NetworkConnect',
        eventId: 3,
        process: 'C:\\Users\\Admin\\AppData\\Local\\Temp\\drop.exe',
        pid: 5100,
        detail: 'Outbound TCP connection to 203.0.113.99:8443',
        confidence: 'observed',
      },
    ]

    const chains = correlateTelemetryEvents(events)
    expect(chains.length).toBeGreaterThanOrEqual(1)
    const stealerChain = chains.find(c => c.category === 'infostealer')
    expect(stealerChain).toBeDefined()
    expect(stealerChain?.severity).toBe('critical')
    expect(stealerChain?.steps.length).toBeGreaterThanOrEqual(2)
  })

  it('correlates Ransomware shadow copy sabotage + mass file encryption', () => {
    const events: TelemetryEvent[] = [
      {
        timestamp: '2026-11-03T16:00:00Z',
        source: 'Sysmon',
        eventType: 'ProcessCreate',
        eventId: 1,
        process: 'locker.exe',
        pid: 8820,
        detail: 'vssadmin delete shadows /all /quiet',
        confidence: 'observed',
      },
      {
        timestamp: '2026-11-03T16:00:03Z',
        source: 'Sysmon',
        eventType: 'FileCreate',
        eventId: 11,
        process: 'locker.exe',
        pid: 8820,
        detail: 'Mass file rename to .locked extension',
        confidence: 'observed',
      },
    ]

    const chains = correlateTelemetryEvents(events)
    expect(chains.some(c => c.category === 'ransomware' && c.severity === 'critical')).toBe(true)
  })
})

