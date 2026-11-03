import type { ExportedFunction, ImportedFunction, PeAnalysis, PeSection } from '../types'
import { impHash, md5, sha1, sha256 } from './hashes'
import { computeFindings, type PartialAnalysis } from './findings'

// ── Decoders & Safe Binary Readers ────────────────────────────────────────────
const asciiDecoder = new TextDecoder('ascii')

const readAscii = (view: DataView, offset: number, maxLen = 512): string => {
  if (offset < 0 || offset >= view.byteLength || maxLen <= 0) return ''
  const bytes: number[] = []
  const end = Math.min(view.byteLength, offset + maxLen)
  for (let i = offset; i < end; i++) {
    const b = view.getUint8(i)
    if (b === 0) break
    if (b >= 32 && b <= 126) bytes.push(b)
  }
  return asciiDecoder.decode(new Uint8Array(bytes))
}

const readU16 = (view: DataView, offset: number, limit = view.byteLength): number =>
  offset >= 0 && offset + 2 <= Math.min(view.byteLength, limit) ? view.getUint16(offset, true) : 0

const readU32 = (view: DataView, offset: number, limit = view.byteLength): number =>
  offset >= 0 && offset + 4 <= Math.min(view.byteLength, limit) ? view.getUint32(offset, true) : 0

const readU64 = (view: DataView, offset: number, limit = view.byteLength): bigint =>
  offset >= 0 && offset + 8 <= Math.min(view.byteLength, limit) ? view.getBigUint64(offset, true) : 0n

// ── Hex helper ────────────────────────────────────────────────────────────────
const hex = (value: number | bigint) => `0x${value.toString(16).toUpperCase()}`

// ── RVA → file offset (hardened against virtual padding & overflow) ───────────
type RawSection = { virtualAddress: number; virtualSize: number; rawOffset: number; rawSize: number }

const rvaToOffset = (rva: number, sections: RawSection[], fileLength: number): number | undefined => {
  if (rva <= 0 || !Number.isFinite(rva)) return undefined
  const s = sections.find(({ virtualAddress, virtualSize, rawSize }) => {
    const span = Math.max(virtualSize, rawSize)
    return virtualAddress > 0 && span > 0 && rva >= virtualAddress && rva - virtualAddress < span
  })
  if (!s) return undefined
  const delta = rva - s.virtualAddress
  if (s.rawSize > 0 && delta >= s.rawSize) return undefined
  const fileOffset = s.rawOffset + delta
  if (fileOffset <= 0 || fileOffset >= fileLength) return undefined
  return fileOffset
}

// ── Section characteristic flags ──────────────────────────────────────────────
const sectionFlags = (chars: number): string[] => {
  const map: Array<[number, string]> = [
    [0x00000020, 'CODE'],
    [0x00000040, 'INIT_DATA'],
    [0x00000080, 'UNINIT_DATA'],
    [0x02000000, 'DISCARDABLE'],
    [0x04000000, 'NOT_CACHED'],
    [0x08000000, 'NOT_PAGED'],
    [0x10000000, 'SHARED'],
    [0x20000000, 'EXECUTE'],
    [0x40000000, 'READ'],
    [0x80000000, 'WRITE'],
  ]
  return map.filter(([mask]) => (chars & mask) !== 0).map(([, name]) => name)
}

// ── DLL characteristics flags ─────────────────────────────────────────────────
const dllCharacteristicsFlags = (flags: number): string[] => {
  const map: Array<[number, string]> = [
    [0x0020, 'HIGH_ENTROPY_VA'],
    [0x0040, 'DYNAMIC_BASE (ASLR)'],
    [0x0080, 'FORCE_INTEGRITY'],
    [0x0100, 'NX_COMPAT (DEP)'],
    [0x0200, 'NO_ISOLATION'],
    [0x0400, 'NO_SEH'],
    [0x0800, 'NO_BIND'],
    [0x1000, 'APPCONTAINER'],
    [0x2000, 'WDM_DRIVER'],
    [0x4000, 'GUARD_CF (CFG)'],
    [0x8000, 'TERMINAL_SERVER_AWARE'],
  ]
  return map.filter(([mask]) => (flags & mask) !== 0).map(([, name]) => name)
}

// ── Subsystem name ────────────────────────────────────────────────────────────
const subsystemName = (id: number): string => {
  const names: Record<number, string> = {
    1: 'Native', 2: 'Windows GUI', 3: 'Windows Console (CUI)',
    5: 'OS/2 Console', 7: 'POSIX Console', 9: 'Windows CE',
    10: 'EFI Application', 11: 'EFI Boot Service Driver',
    12: 'EFI Runtime Driver', 13: 'EFI ROM', 14: 'Xbox',
    16: 'Windows Boot Application',
  }
  return names[id] ?? `Unknown (${id})`
}

// ── Shannon entropy ───────────────────────────────────────────────────────────
const entropy = (bytes: Uint8Array): number => {
  if (!bytes.length) return 0
  const counts = new Uint32Array(256)
  for (const b of bytes) counts[b]++
  return counts.reduce(
    (sum, c) => (c ? sum - (c / bytes.length) * Math.log2(c / bytes.length) : sum),
    0,
  )
}

// ── String extraction (bounded for memory safety) ─────────────────────────────
const MAX_STRING_SCAN_BYTES = 32 * 1024 * 1024

const extractAsciiStrings = (bytes: Uint8Array, minLen = 5): string[] => {
  const results: string[] = []
  let cur = ''
  const limit = Math.min(bytes.length, MAX_STRING_SCAN_BYTES)
  for (let i = 0; i < limit; i++) {
    const b = bytes[i]
    if (b >= 32 && b <= 126) {
      if (cur.length < 512) cur += String.fromCharCode(b)
    } else {
      if (cur.length >= minLen) results.push(cur)
      cur = ''
    }
  }
  if (cur.length >= minLen) results.push(cur)
  return [...new Set(results)].slice(0, 500)
}

const extractUnicodeStrings = (bytes: Uint8Array, minLen = 5): string[] => {
  const results: string[] = []
  let cur = ''
  const limit = Math.min(bytes.length, MAX_STRING_SCAN_BYTES)
  for (let i = 0; i + 1 < limit; i += 2) {
    const lo = bytes[i], hi = bytes[i + 1]
    if (lo >= 32 && lo <= 126 && hi === 0) {
      if (cur.length < 512) cur += String.fromCharCode(lo)
    } else {
      if (cur.length >= minLen) results.push(cur)
      cur = ''
    }
  }
  if (cur.length >= minLen) results.push(cur)
  return [...new Set(results)].slice(0, 300)
}

const extractIndicators = (ascii: string[], unicode: string[]) => {
  const all = [...ascii, ...unicode]
  const urls = new Set<string>()
  const domains = new Set<string>()
  const paths = new Set<string>()
  const ips = new Set<string>()
  for (const s of all) {
    for (const m of s.match(/https?:\/\/[^\s"'<>]{4,}/gi) ?? []) urls.add(m)
    for (const m of s.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi) ?? []) domains.add(m.toLowerCase())
    for (const m of s.match(/[a-z]:\\[^\0<>|?*\n\r]{3,}/gi) ?? []) paths.add(m)
    for (const m of s.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g) ?? []) ips.add(m)
  }
  return {
    urls: [...urls].slice(0, 100),
    domains: [...domains].slice(0, 100),
    paths: [...paths].slice(0, 100),
    ips: [...ips].slice(0, 100),
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main analysis function (hardened against malformed / adversarial PE files)
// ─────────────────────────────────────────────────────────────────────────────
const MAX_PE_FILE_BYTES = 512 * 1024 * 1024
const MAX_SECTIONS = 96
const MAX_IMPORT_DLLS = 256
const MAX_IMPORT_FUNCS_PER_DLL = 1024
const MAX_TOTAL_IMPORTS = 4096
const MAX_EXPORTS = 2048

export async function analyzePortableExecutable(file: File): Promise<PeAnalysis> {
  if (file.size <= 0) throw new Error('O arquivo está vazio (0 bytes).')
  if (file.size > MAX_PE_FILE_BYTES) throw new Error('O arquivo excede o limite local de 512 MB.')

  const buffer = await file.arrayBuffer()
  const view = new DataView(buffer)
  const bytes = new Uint8Array(buffer)
  const fileLen = view.byteLength

  // ── Validate MZ + PE signatures ──────────────────────────────────────────
  if (fileLen < 0x40 || readU16(view, 0) !== 0x5a4d) {
    throw new Error('O arquivo não possui assinatura MZ válida.')
  }

  const peOffset = readU32(view, 0x3c)
  if (peOffset < 0x40 || peOffset > fileLen - 24 || readU32(view, peOffset) !== 0x00004550) {
    throw new Error('O cabeçalho PE (assinatura "PE\\0\\0") não foi encontrado ou está truncado.')
  }

  // ── COFF Header ──────────────────────────────────────────────────────────
  const coffOffset = peOffset + 4
  const machine = readU16(view, coffOffset)
  const rawSectionCount = readU16(view, coffOffset + 2)
  const sectionCount = Math.min(rawSectionCount, MAX_SECTIONS)
  const timestamp = readU32(view, coffOffset + 4)
  const optionalSize = readU16(view, coffOffset + 16)

  // ── Optional Header ───────────────────────────────────────────────────────
  const optionalOffset = coffOffset + 20
  if (optionalSize < 24 || optionalOffset > fileLen - optionalSize) {
    throw new Error('Cabeçalho opcional PE truncado ou com tamanho inválido.')
  }
  const optionalEnd = optionalOffset + optionalSize

  const magic = readU16(view, optionalOffset, optionalEnd)
  if (magic !== 0x10b && magic !== 0x20b) {
    throw new Error('Cabeçalho opcional inválido — não é PE32 (0x10B) nem PE32+ (0x20B).')
  }

  const is64 = magic === 0x20b
  const minOptSize = is64 ? 112 : 96
  if (optionalSize < minOptSize) {
    throw new Error('Cabeçalho opcional menor que o tamanho mínimo exigido pela arquitetura.')
  }

  const entryPoint = readU32(view, optionalOffset + 16, optionalEnd)
  const imageBase = is64
    ? readU64(view, optionalOffset + 24, optionalEnd)
    : BigInt(readU32(view, optionalOffset + 28, optionalEnd))
  const subsystem = readU16(view, optionalOffset + 68, optionalEnd)
  const dllChars = readU16(view, optionalOffset + 70, optionalEnd)

  // ── Data Directories ──────────────────────────────────────────────────────
  const numRvaAndSizes = Math.min(
    16,
    readU32(view, optionalOffset + (is64 ? 108 : 92), optionalEnd),
  )
  const ddBase = optionalOffset + (is64 ? 112 : 96)

  const dirRva = (i: number) =>
    i < numRvaAndSizes ? readU32(view, ddBase + i * 8, optionalEnd) : 0
  const dirSize = (i: number) =>
    i < numRvaAndSizes ? readU32(view, ddBase + i * 8 + 4, optionalEnd) : 0

  const exportDirRva = dirRva(0)
  const importDirRva = dirRva(1)
  const certRva = dirRva(4); const certSize = dirSize(4)
  const debugRva = dirRva(6); const debugSize = dirSize(6)
  const tlsRva = dirRva(9)
  const delayImpRva = dirRva(13); const delayImpSize = dirSize(13)
  const clrRva = dirRva(14); const clrSize = dirSize(14)

  // ── Section Table ─────────────────────────────────────────────────────────
  const sectionBase = optionalOffset + optionalSize
  const rawSections: RawSection[] = []
  const sections: PeSection[] = []

  for (let i = 0; i < sectionCount; i++) {
    const off = sectionBase + i * 40
    if (off < 0 || off > fileLen - 40) break
    const name = readAscii(view, off, 8)
    const virtualSize = readU32(view, off + 8)
    const virtualAddress = readU32(view, off + 12)
    const rawSize = readU32(view, off + 16)
    const rawOffset = readU32(view, off + 20)
    const chars = readU32(view, off + 36)
    rawSections.push({ virtualAddress, virtualSize, rawOffset, rawSize })

    let secEntropy = 0
    if (rawOffset > 0 && rawSize > 0 && rawOffset < bytes.length) {
      const safeEnd = Math.min(bytes.length, rawOffset + Math.min(rawSize, bytes.length - rawOffset))
      secEntropy = entropy(bytes.subarray(rawOffset, safeEnd))
    }

    const isAnomalousSize =
      virtualSize > 0x8000 && (rawSize === 0 || (rawSize > 0 && virtualSize > rawSize * 4))

    sections.push({
      name,
      virtualAddress: hex(virtualAddress),
      virtualSize,
      rawSize,
      characteristics: hex(chars),
      entropy: secEntropy,
      flags: sectionFlags(chars),
      isAnomalousSize,
    })
  }

  // ── Import Table (per-function, bounded & cycle-safe) ─────────────────────
  const importedFunctions: ImportedFunction[] = []
  const importedDlls: string[] = []
  const seenThunkOffsets = new Set<number>()
  const importOff = rvaToOffset(importDirRva, rawSections, fileLen)

  if (importOff !== undefined) {
    for (let i = 0; i < MAX_IMPORT_DLLS; i++) {
      const off = importOff + i * 20
      if (off > fileLen - 20) break
      const iltRva = readU32(view, off)
      const nameRva = readU32(view, off + 12)
      const iatRva = readU32(view, off + 16)
      if (nameRva === 0 && iltRva === 0 && iatRva === 0) break

      const nameOff = rvaToOffset(nameRva, rawSections, fileLen)
      if (nameOff === undefined) continue
      const dllName = readAscii(view, nameOff, 256)
      if (!dllName) continue
      importedDlls.push(dllName)

      const thunkRva = iltRva || iatRva
      const thunkOff = rvaToOffset(thunkRva, rawSections, fileLen)
      if (thunkOff !== undefined && !seenThunkOffsets.has(thunkOff)) {
        seenThunkOffsets.add(thunkOff)
        const stride = is64 ? 8 : 4
        for (let j = 0; j < MAX_IMPORT_FUNCS_PER_DLL; j++) {
          if (importedFunctions.length >= MAX_TOTAL_IMPORTS) break
          const eOff = thunkOff + j * stride
          if (eOff > fileLen - stride) break

          if (is64) {
            const lo = readU32(view, eOff)
            const hi = readU32(view, eOff + 4)
            if (lo === 0 && hi === 0) break
            if ((hi & 0x80000000) !== 0) {
              importedFunctions.push({ dll: dllName, ordinal: lo & 0xffff })
            } else {
              const hintOff = rvaToOffset(lo, rawSections, fileLen)
              if (hintOff !== undefined && hintOff + 2 < fileLen) {
                const fnName = readAscii(view, hintOff + 2, 256)
                if (fnName) importedFunctions.push({ dll: dllName, name: fnName })
              }
            }
          } else {
            const entry = readU32(view, eOff)
            if (entry === 0) break
            if ((entry & 0x80000000) !== 0) {
              importedFunctions.push({ dll: dllName, ordinal: entry & 0xffff })
            } else {
              const hintOff = rvaToOffset(entry & 0x7fffffff, rawSections, fileLen)
              if (hintOff !== undefined && hintOff + 2 < fileLen) {
                const fnName = readAscii(view, hintOff + 2, 256)
                if (fnName) importedFunctions.push({ dll: dllName, name: fnName })
              }
            }
          }
        }
      }
    }
  }

  // ── Export Table (strict bounds checked) ──────────────────────────────────
  const exports: ExportedFunction[] = []
  const exportOff = rvaToOffset(exportDirRva, rawSections, fileLen)

  if (exportOff !== undefined && exportOff <= fileLen - 40) {
    const ordinalBase = readU32(view, exportOff + 16)
    const numAddresses = Math.min(readU32(view, exportOff + 20), MAX_EXPORTS)
    const numNames = Math.min(readU32(view, exportOff + 24), MAX_EXPORTS)
    const eatRva = readU32(view, exportOff + 28)
    const eptRva = readU32(view, exportOff + 32)
    const eotRva = readU32(view, exportOff + 36)

    const eatOff = rvaToOffset(eatRva, rawSections, fileLen)
    const eptOff = rvaToOffset(eptRva, rawSections, fileLen)
    const eotOff = rvaToOffset(eotRva, rawSections, fileLen)

    if (eptOff !== undefined && eotOff !== undefined && eatOff !== undefined) {
      for (let i = 0; i < numNames; i++) {
        if (eptOff + i * 4 > fileLen - 4 || eotOff + i * 2 > fileLen - 2) break
        const nameRva = readU32(view, eptOff + i * 4)
        const ordIdx = readU16(view, eotOff + i * 2)
        if (ordIdx >= numAddresses || eatOff + ordIdx * 4 > fileLen - 4) continue
        const funcRvaV = readU32(view, eatOff + ordIdx * 4)
        const nOff = rvaToOffset(nameRva, rawSections, fileLen)
        const name = nOff !== undefined ? readAscii(view, nOff, 256) : undefined
        exports.push({ name: name || undefined, ordinal: ordinalBase + ordIdx, rva: hex(funcRvaV) })
      }
    }

    if (eatOff !== undefined) {
      const seenOrds = new Set(exports.map(e => e.ordinal))
      for (let i = 0; i < numAddresses; i++) {
        if (eatOff + i * 4 > fileLen - 4) break
        const funcRvaV = readU32(view, eatOff + i * 4)
        if (funcRvaV === 0) continue
        const ord = ordinalBase + i
        if (!seenOrds.has(ord)) {
          seenOrds.add(ord)
          exports.push({ ordinal: ord, rva: hex(funcRvaV) })
        }
      }
    }
  }

  // ── Debug Directory → PDB Path ────────────────────────────────────────────
  let pdbPath: string | undefined
  const dbgOff = rvaToOffset(debugRva, rawSections, fileLen)

  if (dbgOff !== undefined && debugSize >= 28) {
    const numEntries = Math.min(Math.floor(debugSize / 28), 16)
    for (let i = 0; i < numEntries; i++) {
      const off = dbgOff + i * 28
      if (off > fileLen - 28) break
      const type = readU32(view, off + 12)
      if (type === 2) {
        const rawDataPtr = readU32(view, off + 24)
        if (rawDataPtr > 0 && rawDataPtr <= fileLen - 24) {
          const sig = readU32(view, rawDataPtr)
          if (sig === 0x53445352 && rawDataPtr + 24 < fileLen) {
            pdbPath = readAscii(view, rawDataPtr + 24, 512)
          } else if (sig === 0x3031424e && rawDataPtr + 16 < fileLen) {
            pdbPath = readAscii(view, rawDataPtr + 16, 512)
          }
        }
      }
    }
  }

  // ── TLS Callbacks, Authenticode, .NET CLR & Delay Imports ─────────────────
  const hasTlsCallbacks = tlsRva !== 0 && rvaToOffset(tlsRva, rawSections, fileLen) !== undefined
  const isAuthenticodeSigned =
    certRva > 0 && certSize >= 8 && certRva < fileLen && certRva + certSize <= fileLen
  const authenticodeStatus = isAuthenticodeSigned ? 'present_unverified' : 'unsigned'
  const isDotNet =
    (clrRva > 0 && clrSize >= 72) ||
    importedDlls.some(d => d.toLowerCase() === 'mscoree.dll')
  const hasDelayImports = delayImpRva > 0 && delayImpSize > 0
  const apiSetImports = [...new Set(importedDlls.filter(d => /^(?:api|ext)-ms-win-/i.test(d)))]

  // ── Rich Header Fingerprint ───────────────────────────────────────────────
  let richHeaderHash: string | undefined
  const richScanLimit = Math.min(peOffset - 4, fileLen - 8, 1024)
  for (let i = 0x80; i < richScanLimit; i += 4) {
    if (readU32(view, i) === 0x68636952) {
      const xorKey = readU32(view, i + 4)
      for (let j = i - 4; j >= 0x40; j -= 4) {
        if (((readU32(view, j) ^ xorKey) >>> 0) === 0x536e6144) {
          const richBytes = bytes.slice(j, i + 8)
          richHeaderHash = md5(richBytes.buffer)
          break
        }
      }
      break
    }
  }

  // ── Overlay Detection ─────────────────────────────────────────────────────
  let overlay: { offset: number; size: number } | undefined
  if (rawSections.length > 0) {
    const maxEnd = rawSections.reduce(
      (m, s) => (s.rawOffset > 0 && s.rawSize > 0 ? Math.max(m, s.rawOffset + s.rawSize) : m),
      0,
    )
    if (maxEnd > 0 && maxEnd < file.size) {
      overlay = { offset: maxEnd, size: file.size - maxEnd }
    }
  }

  // ── String Extraction & Embedded Manifest Detection ──────────────────────
  const asciiStrings = extractAsciiStrings(bytes)
  const unicodeStrings = extractUnicodeStrings(bytes)
  const indicators = extractIndicators(asciiStrings, unicodeStrings)

  let embeddedManifest: { executionLevel?: string } | undefined
  const combinedStrings = [...asciiStrings, ...unicodeStrings]
  for (const s of combinedStrings) {
    const m = s.match(/level\s*=\s*["'](requireAdministrator|highestAvailable|asInvoker)["']/i)
    if (m) {
      embeddedManifest = { executionLevel: m[1] }
      break
    }
  }

  // ── Hashes ────────────────────────────────────────────────────────────────
  const [hashSha256, hashSha1] = await Promise.all([sha256(buffer), sha1(buffer)])
  const hashMd5 = md5(buffer)
  const hashImpHash = impHash(importedFunctions)

  let isoTimestamp = '1970-01-01T00:00:00.000Z'
  try {
    const dt = new Date(timestamp * 1000)
    if (!Number.isNaN(dt.getTime())) isoTimestamp = dt.toISOString()
  } catch {
    // Fallback to epoch
  }

  const electronFilePath =
    (typeof window !== 'undefined' && window.sentinelGuard?.getFilePath
      ? window.sentinelGuard.getFilePath(file)
      : '') || (file as File & { path?: string }).path
  const partial: PartialAnalysis = {
    fileName: file.name,
    filePath: electronFilePath || undefined,
    fileSize: file.size,
    sha256: hashSha256,
    md5: hashMd5,
    sha1: hashSha1,
    impHash: hashImpHash,
    architecture:
      machine === 0x8664 ? 'x64 (AMD64)' :
        machine === 0x14c ? 'x86 (I386)' :
          machine === 0x1c4 ? 'ARM (Thumb-2)' :
            machine === 0xaa64 ? 'ARM64' :
              `Machine ${hex(machine)}`,
    subsystem: subsystemName(subsystem),
    timestamp: isoTimestamp,
    entryPoint: hex(entryPoint),
    imageBase: hex(imageBase),
    pdbPath: pdbPath || undefined,
    richHeaderHash,
    overlay,
    sections,
    imports: [...new Set(importedDlls)],
    importedFunctions,
    exports,
    strings: asciiStrings,
    unicodeStrings,
    indicators,
    hasTlsCallbacks,
    isAuthenticodeSigned,
    authenticodeStatus,
    isDotNet,
    hasDelayImports,
    apiSetImports,
    embeddedManifest,
    dllCharacteristics: dllCharacteristicsFlags(dllChars),
  }

  const {
    findings,
    riskScore,
    confidenceScore,
    recommendedDecision,
    decisionRationale,
  } = computeFindings(partial)

  return {
    ...partial,
    findings,
    riskScore,
    confidenceScore,
    recommendedDecision,
    decisionRationale,
  }
}
