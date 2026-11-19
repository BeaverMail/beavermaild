// Storage sizes as the panel shows and edits them (binary units: 1 MB = 1024 KB).

export type StorageUnit = 'MB' | 'GB'

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(2)} GB`
}

/** Bytes for an amount typed in a form; undefined when empty or not above 0. */
export function storageToBytes(amount: string, unit: StorageUnit): number | undefined {
  const n = Number(amount)
  if (!amount || !Number.isFinite(n) || n <= 0) return undefined
  return Math.round(n * (unit === 'GB' ? 1024 ** 3 : 1024 ** 2))
}

/** Form value for a byte count: whole GB, else MB with two decimals; empty for 0. */
export function bytesToStorage(bytes: number | undefined): { amount: string; unit: StorageUnit } {
  if (!bytes) return { amount: '', unit: 'MB' }
  const gb = 1024 ** 3
  const mb = 1024 ** 2
  if (bytes >= gb && bytes % gb === 0) return { amount: String(bytes / gb), unit: 'GB' }
  if (bytes >= mb && bytes % mb === 0) return { amount: String(bytes / mb), unit: 'MB' }
  return { amount: String(Math.round((bytes / mb) * 100) / 100), unit: 'MB' }
}
