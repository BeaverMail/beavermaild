<script lang="ts">
import { ScrollText, X } from '@lucide/svelte'
import { ApiError, fetchLogs, type LogEntry } from '$lib/api'
import { me } from '$lib/session'

let entries = $state<LogEntry[]>([])
let error = $state('')
let loaded = $state(false)
let refreshing = $state(false)
let loadingOlder = $state(false)
let level = $state('')
let q = $state('')
let hasMore = $state(true)
let selected = $state<LogEntry | null>(null)

const isAdmin = $derived($me?.role === 'admin')

async function load() {
  if (!isAdmin) return
  refreshing = true
  error = ''
  hasMore = true
  try {
    const out = await fetchLogs({
      level: level || undefined,
      q: q.trim() || undefined,
      limit: 200
    })
    entries = out.entries ?? []
  } catch (e) {
    error = e instanceof ApiError ? e.message : 'failed to load logs'
  } finally {
    loaded = true
    refreshing = false
  }
}

async function loadOlder() {
  if (!isAdmin || entries.length === 0) return
  loadingOlder = true
  error = ''
  try {
    const oldest = entries[entries.length - 1]
    const out = await fetchLogs({
      level: level || undefined,
      q: q.trim() || undefined,
      limit: 200,
      before: oldest.time
    })
    const more = out.entries ?? []
    if (more.length === 0) {
      hasMore = false
      return
    }
    const seen = new Set(entries.map((e) => `${e.time}|${e.msg}|${attrsText(e.attrs)}`))
    const merged = [...entries]
    for (const e of more) {
      const key = `${e.time}|${e.msg}|${attrsText(e.attrs)}`
      if (seen.has(key)) continue
      merged.push(e)
      seen.add(key)
    }
    entries = merged
    if (more.length < 200) hasMore = false
  } catch (e) {
    error = e instanceof ApiError ? e.message : 'failed to load older logs'
  } finally {
    loadingOlder = false
  }
}

$effect(() => {
  if (!isAdmin) return
  void load()
})

function levelClass(lvl: string) {
  switch (lvl.toUpperCase()) {
    case 'ERROR':
      return 'bg-red-100 text-red-800'
    case 'WARN':
    case 'WARNING':
      return 'bg-amber-100 text-amber-900'
    case 'DEBUG':
      return 'bg-gray-100 text-gray-600'
    default:
      return 'bg-blue-100 text-blue-800'
  }
}

// valueText renders an attribute value; objects as JSON instead of "[object Object]".
function valueText(v: unknown): string {
  if (v !== null && typeof v === 'object') return JSON.stringify(v, null, 2)
  return String(v)
}

function attrsText(attrs?: Record<string, unknown>) {
  if (!attrs) return ''
  return Object.entries(attrs)
    .map(([k, v]) => `${k}=${valueText(v)}`)
    .join(' ')
}

function onKeydown(ev: KeyboardEvent) {
  if (ev.key === 'Escape') selected = null
}

function formatTime(t: string) {
  try {
    return new Date(t).toLocaleString()
  } catch {
    return t
  }
}
</script>

<div class="mb-4 flex items-center justify-between gap-3">
  <div class="flex items-center gap-2">
    <ScrollText class="size-5 text-gray-700" />
    <h1 class="text-xl font-semibold text-gray-900">Logs</h1>
  </div>
  {#if isAdmin}
    <button
      type="button"
      class="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
      disabled={refreshing}
      onclick={() => void load()}
    >
      {refreshing ? 'Refreshing…' : 'Refresh'}
    </button>
  {/if}
</div>

{#if !isAdmin}
  <p class="text-sm text-red-600">admin role required</p>
{:else}
  <p class="mb-4 max-w-xl text-sm text-gray-600">
    Rotating process logs on disk. Filter by level or search; Load older pages further back.
  </p>

  <form
    class="mb-6 flex flex-wrap items-end gap-3"
    onsubmit={(e) => {
      e.preventDefault()
      void load()
    }}
  >
    <label class="block text-sm">
      <span class="mb-1 block font-medium text-gray-700">Min level</span>
      <select class="min-w-[9rem] rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm" bind:value={level}>
        <option value="">Info+</option>
        <option value="debug">Debug</option>
        <option value="info">Info</option>
        <option value="warn">Warn</option>
        <option value="error">Error</option>
      </select>
    </label>
    <label class="block min-w-[12rem] flex-1 text-sm">
      <span class="mb-1 block font-medium text-gray-700">Search</span>
      <input
        class="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm"
        type="search"
        placeholder="smtp, email, queue…"
        bind:value={q}
      >
    </label>
    <button
      type="submit"
      class="rounded-lg bg-brand-700 px-4 py-2 text-sm font-medium text-white hover:bg-brand-800 disabled:opacity-50"
      disabled={refreshing}
    >
      Apply
    </button>
  </form>

  {#if !loaded}
    <p class="text-sm text-gray-500">Loading…</p>
  {:else}
    {#if error}
      <p class="mb-4 text-sm text-red-600">{error}</p>
    {/if}

    {#if entries.length === 0}
      <p class="text-sm text-gray-500">No matching log entries.</p>
    {:else}
      <div class="overflow-x-auto rounded-xl border border-gray-200 bg-white">
        <table class="min-w-full text-left text-sm">
          <thead class="border-b border-gray-100 bg-gray-50 text-xs uppercase text-gray-500">
            <tr>
              <th class="px-4 py-3 font-medium">Time</th>
              <th class="px-4 py-3 font-medium">Level</th>
              <th class="px-4 py-3 font-medium">Message</th>
              <th class="px-4 py-3 font-medium">Attrs</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            {#each entries as e, i (e.time + e.msg + String(i))}
              <tr
                class="cursor-pointer align-top hover:bg-gray-50 focus:bg-gray-50 focus:outline-none"
                tabindex="0"
                aria-label="Log entry details"
                onclick={() => (selected = e)}
                onkeydown={(ev) => {
                  if (ev.key === 'Enter' || ev.key === ' ') {
                    ev.preventDefault()
                    selected = e
                  }
                }}
              >
                <td class="whitespace-nowrap px-4 py-3 font-mono text-xs text-gray-500">{formatTime(e.time)}</td>
                <td class="px-4 py-3">
                  <span class="rounded px-2 py-0.5 text-xs font-semibold {levelClass(e.level)}">{e.level}</span>
                </td>
                <td class="max-w-xs truncate px-4 py-3 font-medium text-gray-900">{e.msg}</td>
                <td class="max-w-md truncate px-4 py-3 font-mono text-xs text-gray-500" title={attrsText(e.attrs)}>
                  {attrsText(e.attrs)}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if hasMore}
        <div class="mt-4">
          <button
            type="button"
            class="rounded-lg border border-gray-200 bg-white px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            disabled={loadingOlder}
            onclick={() => void loadOlder()}
          >
            {loadingOlder ? 'Loading…' : 'Load older'}
          </button>
        </div>
      {:else}
        <p class="mt-4 text-sm text-gray-500">No older matching entries.</p>
      {/if}
    {/if}
  {/if}
{/if}

<svelte:window onkeydown={onKeydown} />

{#if selected}
  {@const e = selected}
  <div class="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto p-4 sm:p-8">
    <!-- Backdrop: a real button so click-to-close is keyboard/screen-reader accessible (Escape also closes). -->
    <button
      type="button"
      class="fixed inset-0 cursor-default bg-black/40"
      aria-label="Close details"
      tabindex="-1"
      onclick={() => (selected = null)}
    ></button>
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="log-entry-title"
      class="relative my-4 w-full max-w-3xl rounded-xl border border-gray-200 bg-white shadow-lg"
    >
      <div class="flex items-start justify-between gap-3 border-b border-gray-100 px-5 py-4">
        <div class="min-w-0">
          <h2 id="log-entry-title" class="text-lg font-semibold break-words text-gray-900">
            <span class="mr-2 rounded px-2 py-0.5 align-middle text-xs font-semibold {levelClass(e.level)}"
              >{e.level}</span
            >
            {e.msg}
          </h2>
          <p class="mt-1 font-mono text-xs text-gray-500">{formatTime(e.time)} ({e.time})</p>
        </div>
        <button
          type="button"
          class="rounded-lg p-1 text-gray-500 hover:bg-gray-100"
          onclick={() => (selected = null)}
          aria-label="Close"
        >
          <X class="size-5" />
        </button>
      </div>
      {#if e.attrs && Object.keys(e.attrs).length > 0}
        <dl class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 px-5 py-4 text-sm">
          {#each Object.entries(e.attrs) as [k, v] (k)}
            <dt class="font-mono text-xs text-gray-500">{k}</dt>
            <dd class="font-mono text-xs break-all whitespace-pre-wrap text-gray-900">{valueText(v)}</dd>
          {/each}
        </dl>
      {:else}
        <p class="px-5 py-4 text-sm text-gray-500">No attributes.</p>
      {/if}
    </div>
  </div>
{/if}
