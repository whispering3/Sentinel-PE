/** Left-rotate a 32-bit unsigned integer */
const rotL = (n: number, s: number) => ((n << s) | (n >>> (32 - s))) >>> 0

/**
 * MD5 — pure TypeScript, no external dependencies.
 * Used for ImpHash and Rich Header fingerprinting
 * (Web Crypto API does not support MD5).
 */
export function md5(buffer: ArrayBuffer): string {
  // Precomputed: T[i] = floor(abs(sin(i+1)) * 2^32)
  const T = Array.from({ length: 64 }, (_, i) => (Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0)
  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ]

  const src = new Uint8Array(buffer)
  const L = src.length
  const paddedLen = Math.ceil((L + 9) / 64) * 64
  const msg = new Uint8Array(paddedLen)
  msg.set(src)
  msg[L] = 0x80

  // Append bit-length as 64-bit little-endian
  const dv = new DataView(msg.buffer)
  dv.setUint32(paddedLen - 8, (L * 8) >>> 0, true)
  dv.setUint32(paddedLen - 4, Math.floor(L / 0x20000000) >>> 0, true)

  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476

  for (let i = 0; i < paddedLen; i += 64) {
    const M = Array.from({ length: 16 }, (_, j) => dv.getUint32(i + j * 4, true))
    let [A, B, C, D] = [a, b, c, d]

    for (let j = 0; j < 64; j++) {
      let F: number, g: number
      if (j < 16)      { F = (B & C) | (~B & D); g = j }
      else if (j < 32) { F = (D & B) | (~D & C); g = (5 * j + 1) % 16 }
      else if (j < 48) { F = B ^ C ^ D;           g = (3 * j + 5) % 16 }
      else             { F = C ^ (B | ~D);         g = (7 * j) % 16 }

      F = (F + A + T[j] + M[g]) >>> 0
      A = D; D = C; C = B
      B = (B + rotL(F, S[j])) >>> 0
    }

    a = (a + A) >>> 0; b = (b + B) >>> 0
    c = (c + C) >>> 0; d = (d + D) >>> 0
  }

  return [a, b, c, d]
    .map(n => [0, 8, 16, 24].map(s => ((n >>> s) & 0xff).toString(16).padStart(2, '0')).join(''))
    .join('')
}

/** SHA-1 via Web Crypto API */
export async function sha1(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', buffer)
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
}

/** SHA-256 via Web Crypto API */
export async function sha256(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buffer)
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * ImpHash — standard malware clustering fingerprint.
 * Algorithm: normalize imports (lowercase, strip DLL extension),
 * join with commas, MD5 the resulting string.
 * Compatible with pefile / CAPE / MalwareBazaar conventions.
 */
const DLL_EXT = /\.(dll|ocx|sys|exe|drv|cpl|scr)$/i

export function impHash(functions: Array<{ dll: string; name?: string; ordinal?: number }>): string {
  if (!functions.length) return ''
  const parts = functions.map(({ dll, name, ordinal }) => {
    const normDll = dll.replace(DLL_EXT, '').toLowerCase()
    const normFn = name ? name.toLowerCase() : `ord${ordinal ?? 0}`
    return `${normDll}.${normFn}`
  })
  return md5(new TextEncoder().encode(parts.join(',')).buffer)
}

