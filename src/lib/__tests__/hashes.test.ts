import { describe, expect, it } from 'vitest'
import { impHash, md5, sha1, sha256 } from '../hashes'

describe('hashes', () => {
  it('computes MD5 accurately against standard test vectors', () => {
    const enc = new TextEncoder()
    expect(md5(enc.encode('').buffer)).toBe('d41d8cd98f00b204e9800998ecf8427e')
    expect(md5(enc.encode('The quick brown fox jumps over the lazy dog').buffer)).toBe('9e107d9d372bb6826bd81d3542a419d6')
    expect(md5(enc.encode('hello').buffer)).toBe('5d41402abc4b2a76b9719d911017c592')
  })

  it('computes SHA-1 accurately', async () => {
    const enc = new TextEncoder()
    const result = await sha1(enc.encode('hello').buffer)
    expect(result).toBe('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d')
  })

  it('computes SHA-256 accurately', async () => {
    const enc = new TextEncoder()
    const result = await sha256(enc.encode('hello').buffer)
    expect(result).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
  })

  it('computes ImpHash correctly following pefile standard', () => {
    // ImpHash should normalize DLL extension, lowercase, and MD5 the comma-separated string
    const functions = [
      { dll: 'KERNEL32.DLL', name: 'CreateFileW' },
      { dll: 'advapi32.dll', ordinal: 15 },
    ]
    const hash = impHash(functions)
    // "kernel32.createfilew,advapi32.ord15"
    const expected = md5(new TextEncoder().encode('kernel32.createfilew,advapi32.ord15').buffer)
    expect(hash).toBe(expected)
  })

  it('handles empty import list in impHash', () => {
    expect(impHash([])).toBe('')
  })
})

