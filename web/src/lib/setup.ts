// Cached first-install status; used by the root layout route guard.
import { goto } from '$app/navigation'
import { fetchSetup } from '$lib/api'

let cached: boolean | null = null
let inflight: Promise<boolean> | null = null

/** Returns whether the greenfield setup wizard is still required. */
export async function setupNeeded(): Promise<boolean> {
  if (cached !== null) return cached
  if (inflight) return inflight
  inflight = fetchSetup()
    .then((st) => {
      cached = st.needed
      return cached
    })
    .finally(() => {
      inflight = null
    })
  return inflight
}

/** Clears cache (forces next setupNeeded to hit the API). */
export function clearSetupCache() {
  cached = null
  inflight = null
}

/** After successful bootstrap: setup is done without another GET. */
export function markSetupComplete() {
  cached = false
  inflight = null
}

/**
 * Redirects to /setup when needed, or away from /setup when complete.
 * Returns true if a redirect was triggered.
 */
export async function enforceSetupPath(pathname: string): Promise<boolean> {
  let needed: boolean
  try {
    needed = await setupNeeded()
  } catch {
    return false
  }
  const onSetup = pathname === '/setup' || pathname.startsWith('/setup/')
  if (needed && !onSetup) {
    await goto('/setup')
    return true
  }
  if (!needed && onSetup) {
    await goto('/login')
    return true
  }
  return false
}
