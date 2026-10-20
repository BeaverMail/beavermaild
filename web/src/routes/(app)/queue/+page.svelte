<script lang="ts">
import { ListOrdered } from '@lucide/svelte'
import { goto } from '$app/navigation'
import { page } from '$app/state'
import {
  ApiError,
  cancelQueueEntry,
  fetchQueue,
  holdQueueEntry,
  type QueueEntry,
  retryQueueEntry,
  unholdQueueEntry
} from '$lib/api'
import { me } from '$lib/session'

type Tab = 'pending' | 'completed'

let entries = $state<QueueEntry[]>([])
let error = $state('')
let loading = $state(true)
let busyId = $state<number | null>(null)

const isAdmin = $derived($me?.role === 'admin')
const tab = $derived<Tab>(page.url.searchParams.get('tab') === 'completed' ? 'completed' : 'pending')

async function load(view: Tab) {
  loading = true
  error = ''
  try {
    if (view === 'pending') {
      entries = await fetchQueue(false)
    } else {
      const all = await fetchQueue(true)
      entries = all.filter((e) => e.pending === 0)
    }
  } catch (e) {
    error = e instanceof ApiError ? e.message : 'failed to load queue'
  } finally {
    loading = false
  }
}

$effect(() => {
  if (!isAdmin) {
    loading = false
    error = 'admin role required'
    entries = []
    return
  }
  void load(tab)
})

async function setTab(next: Tab) {
  if (next === tab) return
  const url = new URL(page.url)
  if (next === 'pending') url.searchParams.delete('tab')
  else url.searchParams.set('tab', 'completed')
  await goto(`${url.pathname}${url.search}`, { replaceState: true, keepFocus: true, noScroll: true })
}

async function runAction(id: number, fn: () => Promise<void>) {
  busyId = id
  error = ''
  try {
    await fn()
    await load(tab)
  } catch (e) {
    error = e instanceof ApiError ? e.message : 'queue action failed'
  } finally {
    busyId = null
  }
}

function tabClass(active: boolean) {
  return active
    ? 'border-brand-700 text-brand-900'
    : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-800'
}

function btnClass(danger = false) {
  return danger
    ? 'rounded-md border border-red-200 bg-white px-2 py-1 text-xs font-medium text-red-700 hover:bg-red-50 disabled:opacity-50'
    : 'rounded-md border border-gray-200 bg-white px-2 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50'
}

function formatMS(ms: number): string {
  if (!ms) return '—'
  return new Date(ms).toLocaleString()
}

function formatCreated(sec: number): string {
  if (!sec) return '—'
  const ms = sec > 1e12 ? sec : sec * 1000
  return new Date(ms).toLocaleString()
}
</script>

<div class="mb-4 flex items-center gap-2">
  <ListOrdered class="size-5 text-gray-700" />
  <h1 class="text-xl font-semibold text-gray-900">Outbound queue</h1>
</div>

{#if isAdmin}
  <div class="mb-6 border-b border-gray-200" role="tablist" aria-label="Queue view">
    <div class="flex gap-6">
      <button
        type="button"
        role="tab"
        aria-selected={tab === 'pending'}
        class="-mb-px border-b-2 px-0.5 pb-2.5 text-sm font-medium {tabClass(tab === 'pending')}"
        onclick={() => setTab('pending')}
      >
        Pending
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={tab === 'completed'}
        class="-mb-px border-b-2 px-0.5 pb-2.5 text-sm font-medium {tabClass(tab === 'completed')}"
        onclick={() => setTab('completed')}
      >
        Completed
      </button>
    </div>
  </div>
{/if}

{#if loading}
  <p class="text-sm text-gray-500">Loading…</p>
{:else if error}
  <p class="text-sm text-red-600">{error}</p>
{:else if entries.length === 0}
  <p class="text-sm text-gray-500">
    {tab === 'pending' ? 'No pending queue entries.' : 'No completed queue entries.'}
  </p>
{:else}
  <div class="space-y-4">
    {#each entries as e (e.id)}
      <div class="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
        <div class="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-gray-100 bg-gray-50 px-4 py-3 text-sm">
          <span class="font-medium text-gray-900">#{e.id}</span>
          <span class="text-gray-600">from {e.return_path || '<>'}</span>
          <span class="text-gray-500">{e.size} bytes</span>
          <span class="text-gray-500">created {formatCreated(e.created)}</span>
          {#if e.completed_ms}
            <span class="text-gray-500">completed {formatMS(e.completed_ms)}</span>
          {:else}
            <span class="text-gray-500">pending {e.pending}</span>
          {/if}
          {#if e.held}
            <span class="rounded bg-amber-100 px-1.5 py-0.5 text-xs font-medium text-amber-800">held</span>
          {/if}
          {#if tab === 'pending' && isAdmin}
            <div class="ml-auto flex flex-wrap gap-2">
              <button
                type="button"
                class={btnClass()}
                disabled={busyId === e.id}
                onclick={() => runAction(e.id, () => retryQueueEntry(e.id))}
              >
                Retry now
              </button>
              {#if e.held}
                <button
                  type="button"
                  class={btnClass()}
                  disabled={busyId === e.id}
                  onclick={() => runAction(e.id, () => unholdQueueEntry(e.id))}
                >
                  Unhold
                </button>
              {:else}
                <button
                  type="button"
                  class={btnClass()}
                  disabled={busyId === e.id}
                  onclick={() => runAction(e.id, () => holdQueueEntry(e.id))}
                >
                  Hold
                </button>
              {/if}
              <button
                type="button"
                class={btnClass(true)}
                disabled={busyId === e.id}
                onclick={() => {
                  if (confirm(`Cancel queue entry #${e.id}? No bounce will be sent.`)) {
                    void runAction(e.id, () => cancelQueueEntry(e.id))
                  }
                }}
              >
                Cancel
              </button>
            </div>
          {/if}
        </div>
        <table class="min-w-full divide-y divide-gray-100 text-sm">
          <thead>
            <tr class="text-left text-xs text-gray-500">
              <th class="px-4 py-2 font-medium">Recipient</th>
              <th class="px-4 py-2 font-medium">Status</th>
              <th class="px-4 py-2 font-medium">Retry</th>
              <th class="px-4 py-2 font-medium">Next due</th>
              <th class="px-4 py-2 font-medium">Last attempt</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-50">
            {#each e.recipients as r (r.address)}
              <tr>
                <td class="px-4 py-2 font-medium text-gray-900">{r.address}</td>
                <td class="px-4 py-2 text-gray-600">{r.status}</td>
                <td class="px-4 py-2 text-gray-600">{r.retry}</td>
                <td class="px-4 py-2 text-gray-500">{formatMS(r.next_due_ms)}</td>
                <td class="px-4 py-2 text-gray-500">{formatMS(r.last_attempt_ms)}</td>
              </tr>
              {#if r.last_diag}
                <tr>
                  <td
                    colspan="5"
                    class="px-4 pb-2 pt-0 font-mono text-xs break-all {r.status === 'delivered' ? 'text-gray-500' : 'text-red-700'}"
                  >
                    {r.last_diag}
                  </td>
                </tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
    {/each}
  </div>
{/if}
