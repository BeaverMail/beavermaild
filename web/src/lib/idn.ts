// Display form of internationalized domains. The server stores and returns every domain as
// A-labels ("xn--bcher-kva.example", RFC 6531 3.2); people read the Unicode form ("bücher.example").
// Browsers have no native A-label → Unicode conversion, so this is the Punycode decoder of RFC 3492.

const base = 36
const tMin = 1
const tMax = 26

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  delta = firstTime ? Math.floor(delta / 700) : delta >> 1
  delta += Math.floor(delta / numPoints)
  let k = 0
  while (delta > ((base - tMin) * tMax) >> 1) {
    delta = Math.floor(delta / (base - tMin))
    k += base
  }
  return k + Math.floor(((base - tMin + 1) * delta) / (delta + 38))
}

function digit(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 22 // 0-9 → 26-35
  if (c >= 0x41 && c <= 0x5a) return c - 0x41
  if (c >= 0x61 && c <= 0x7a) return c - 0x61
  return base
}

/** Decodes one Punycode label (without "xn--"); throws on malformed input. */
function decodeLabel(input: string): string {
  const out: number[] = []
  let n = 128
  let i = 0
  let bias = 72
  const b = Math.max(input.lastIndexOf('-'), 0)
  for (let j = 0; j < b; j++) out.push(input.charCodeAt(j))
  for (let idx = b > 0 ? b + 1 : 0; idx < input.length; ) {
    const oldi = i
    let w = 1
    for (let k = base; ; k += base) {
      if (idx >= input.length) throw new Error('punycode: truncated')
      const d = digit(input.charCodeAt(idx++))
      if (d >= base) throw new Error('punycode: bad digit')
      i += d * w
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias
      if (d < t) break
      w *= base - t
    }
    const len = out.length + 1
    bias = adapt(i - oldi, len, oldi === 0)
    n += Math.floor(i / len)
    i %= len
    if (n > 0x10ffff) throw new Error('punycode: out of range')
    out.splice(i++, 0, n)
  }
  return String.fromCodePoint(...out)
}

/** The Unicode form of a domain for display; a label that does not decode stays as it is. */
export function displayDomain(name: string): string {
  return name
    .split('.')
    .map((label) => {
      if (!label.toLowerCase().startsWith('xn--')) return label
      try {
        return decodeLabel(label.slice(4))
      } catch {
        return label
      }
    })
    .join('.')
}

/** An address with its domain in Unicode form, for display. */
export function displayEmail(addr: string): string {
  const at = addr.lastIndexOf('@')
  return at < 0 ? addr : addr.slice(0, at + 1) + displayDomain(addr.slice(at + 1))
}
