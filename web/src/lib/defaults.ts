// Server-wide defaults as text, for fields a domain or mailbox leaves to them.
import type { ServerDefaults } from './api'
import { formatBytes } from './bytes'

// Each returns null until the defaults are loaded (or when they cannot be read).
export function storageDefault(d: ServerDefaults | null): string | null {
  if (!d) return null
  return d.storage_bytes ? formatBytes(d.storage_bytes) : 'unlimited'
}

export function messagesDefault(d: ServerDefaults | null): string | null {
  if (!d) return null
  return d.messages ? `${d.messages.toLocaleString()} messages` : 'unlimited'
}

export function sendDefault(d: ServerDefaults | null): string | null {
  if (!d) return null
  return d.send_max_messages ? `${d.send_max_messages} per ${d.send_window}` : 'no limit'
}

/** Placeholder for an empty override field. */
export function globalPlaceholder(value: string | null): string {
  return value ? `global: ${value}` : 'global default'
}
