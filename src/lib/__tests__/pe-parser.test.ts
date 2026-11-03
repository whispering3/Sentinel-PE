import { describe, expect, it } from 'vitest'
import { analyzePortableExecutable } from '../pe-parser'

// Helper to construct a minimal valid PE32+ (x64) buffer in memory
function buildMinimalPe64(): Uint8Array {
  const buf = new Uint8Array(1024)
  const view = new DataView(buf.buffer)

  // MZ signature
  view.setUint16(0x00, 0x5a4d, true) // 'MZ'
  view.setUint32(0x3c, 0x80, true)   // e_lfanew = 0x80 (PE offset)

  // PE signature at 0x80
  const peOff = 0x80
  view.setUint32(peOff, 0x00004550, true) // 'PE\0\0'

  // COFF Header (20 bytes)
  view.setUint16(peOff + 4, 0x8664, true)  // Machine: x64
  view.setUint16(peOff + 6, 1, true)       // Number of sections: 1
  view.setUint32(peOff + 8, 1700000000, true) // TimeDateStamp
  view.setUint16(peOff + 20, 240, true)    // SizeOfOptionalHeader (240 for PE32+)
  view.setUint16(peOff + 22, 0x0022, true) // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

  // Optional Header (PE32+)
  const optOff = peOff + 24
  view.setUint16(optOff, 0x020b, true)     // Magic: PE32+ (64-bit)
  view.setUint32(optOff + 16, 0x1000, true)// AddressOfEntryPoint
  view.setBigUint64(optOff + 24, 0x140000000n, true) // ImageBase
  view.setUint16(optOff + 68, 2, true)     // Subsystem: Windows GUI (2)
  view.setUint16(optOff + 70, 0x0140, true)// DllCharacteristics: DYNAMIC_BASE | NX_COMPAT

  // Number of RvaAndSizes = 16
  view.setUint32(optOff + 108, 16, true)

  // Section Table (.text section header at optOff + 240)
  const secOff = optOff + 240
  const secName = new TextEncoder().encode('.text')
  buf.set(secName, secOff)
  view.setUint32(secOff + 8, 0x200, true)   // VirtualSize
  view.setUint32(secOff + 12, 0x1000, true) // VirtualAddress
  view.setUint32(secOff + 16, 0x200, true)  // SizeOfRawData
  view.setUint32(secOff + 20, 0x200, true)  // PointerToRawData
  view.setUint32(secOff + 36, 0x60000020, true) // Characteristics: CODE | EXECUTE | READ

  // Fill .text raw data with NOPs (0x90) and RET (0xc3)
  for (let i = 0x200; i < 0x200 + 0x200; i++) {
    buf[i] = 0x90
  }
  buf[0x200] = 0xc3

  return buf
}

describe('PE parser & malformed binary resilience', () => {
  it('throws on non-PE files and empty files', async () => {
    const emptyFile = new File([], 'empty.exe')
    await expect(analyzePortableExecutable(emptyFile)).rejects.toThrow('vazio')

    const invalidFile = new File([new Uint8Array([1, 2, 3, 4])], 'not_a_pe.bin')
    await expect(analyzePortableExecutable(invalidFile)).rejects.toThrow('assinatura MZ')
  })

  it('rejects MZ file with out-of-bounds e_lfanew pointer', async () => {
    const buf = new Uint8Array(128)
    const view = new DataView(buf.buffer)
    view.setUint16(0, 0x5a4d, true)
    view.setUint32(0x3c, 0xffff0000, true) // Out-of-bounds PE offset
    const file = new File([buf.buffer as ArrayBuffer], 'bad_e_lfanew.exe')
    await expect(analyzePortableExecutable(file)).rejects.toThrow('cabeçalho PE')
  })

  it('rejects PE with truncated Optional Header size', async () => {
    const buf = buildMinimalPe64()
    const view = new DataView(buf.buffer)
    view.setUint16(0x80 + 20, 32, true) // SizeOfOptionalHeader = 32 (< 112 required for PE32+)
    const file = new File([buf.buffer as ArrayBuffer], 'truncated_opt.exe')
    await expect(analyzePortableExecutable(file)).rejects.toThrow('Cabeçalho opcional')
  })

  it('safely handles malformed section table with huge section count and out-of-bounds rawSize', async () => {
    const buf = buildMinimalPe64()
    const view = new DataView(buf.buffer)
    // Set absurd section count (65535) and out-of-bounds rawSize (0x0fffffff)
    view.setUint16(0x80 + 6, 65535, true)
    const secOff = 0x80 + 24 + 240
    view.setUint32(secOff + 16, 0x0fffffff, true) // SizeOfRawData >> file size
    // Also point Export & Import directory RVAs into the section near EOF
    const optOff = 0x80 + 24
    const ddBase = optOff + 112
    view.setUint32(ddBase, 0x11f0, true)     // Export RVA near end of section
    view.setUint32(ddBase + 8, 0x11f0, true) // Import RVA near end of section

    const file = new File([buf.buffer as ArrayBuffer], 'malformed_sections.exe')
    const analysis = await analyzePortableExecutable(file)
    expect(analysis.sections.length).toBeLessThanOrEqual(96)
    expect(analysis.sections[0].entropy).toBeGreaterThanOrEqual(0)
  })

  it('correctly parses minimal synthetic 64-bit PE binary', async () => {
    const bytes = buildMinimalPe64()
    const file = new File([bytes.buffer as ArrayBuffer], 'minimal.exe')
    const analysis = await analyzePortableExecutable(file)

    expect(analysis.fileName).toBe('minimal.exe')
    expect(analysis.architecture).toContain('x64')
    expect(analysis.subsystem).toBe('Windows GUI')
    expect(analysis.entryPoint).toBe('0x1000')
    expect(analysis.imageBase).toBe('0x140000000')
    expect(analysis.sections).toHaveLength(1)
    expect(analysis.sections[0].name).toBe('.text')
    expect(analysis.sections[0].flags).toContain('EXECUTE')
    expect(analysis.dllCharacteristics).toContain('DYNAMIC_BASE (ASLR)')
    expect(analysis.dllCharacteristics).toContain('NX_COMPAT (DEP)')
    expect(analysis.riskScore).toBeDefined()
    expect(analysis.findings.length).toBeGreaterThan(0)
  })
})
