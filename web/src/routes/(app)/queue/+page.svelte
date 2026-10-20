<script lang="ts">
import { ListOrdered, X } from '@lucide/svelte'
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
import ConfirmDialog from '$lib/ConfirmDialog.svelte'
import { me } from '$lib/session'

type Tab = 'pending' | 'completed'

let entries = $state<QueueEntry[]>([])
let error = $state('')
let loading = $state(true)
let busyId = $state<number | null>(null)
let openId = $state<number | null>(null)
let cancelTarget = $state<number | null>(null)
const openEntry = $derived(entries.find((e) => e.id === openId) ?? null)

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

type EntryStatus = 'pending' | 'held' | 'delivered' | 'failed' | 'partial'

function entryStatus(e: QueueEntry): EntryStatus {
  if (e.pending > 0) return e.held ? 'held' : 'pending'
  const delivered = e.recipients.filter((r) => r.status === 'delivered').length
  if (delivered === e.recipients.length) return 'delivered'
  return delivered === 0 ? 'failed' : 'partial'
}

const statusBadge: Record<string, string> = {
  delivered: 'bg-emerald-50 text-emerald-800',
  failed: 'bg-red-50 text-red-700',
  partial: 'bg-amber-50 text-amber-800',
  held: 'bg-amber-100 text-amber-800',
  pending: 'bg-gray-100 text-gray-700'
}

function recipientsLabel(e: QueueEntry): string {
  const first = e.recipients[0]?.address ?? '—'
  return e.recipients.length > 1 ? `${first} +${e.recipients.length - 1}` : first
}

function formatSize(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

function onKeydown(ev: KeyboardEvent) {
  if (ev.key === 'Escape') openId = null
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
  <div class="overflow-x-auto rounded-xl border border-gray-200 bg-white shadow-sm">
    <table class="min-w-full divide-y divide-gray-200 text-sm">
      <thead class="bg-gray-50">
        <tr class="text-left">
          <th class="px-4 py-3 font-medium text-gray-600">#</th>
          <th class="px-4 py-3 font-medium text-gray-600">From</th>
          <th class="px-4 py-3 font-medium text-gray-600">To</th>
          <th class="px-4 py-3 font-medium text-gray-600">Status</th>
          <th class="px-4 py-3 font-medium text-gray-600">{tab === 'pending' ? 'Created' : 'Completed'}</th>
          <th class="px-4 py-3 text-right font-medium text-gray-600">Size</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-100">
        {#each entries as e (e.id)}
          {@const st = entryStatus(e)}
          <tr
            class="cursor-pointer hover:bg-gray-50 focus:bg-gray-50 focus:outline-none"
            tabindex="0"
            aria-label="Queue entry {e.id} details"
            onclick={() => (openId = e.id)}
            onkeydown={(ev) => {
              if (ev.key === 'Enter' || ev.key === ' ') {
                ev.preventDefault()
                openId = e.id
              }
            }}
          >
            <td class="px-4 py-2.5 font-medium text-gray-900">{e.id}</td>
            <td class="max-w-56 truncate px-4 py-2.5 text-gray-700">{e.return_path || '<>'}</td>
            <td class="max-w-64 truncate px-4 py-2.5 text-gray-700">{recipientsLabel(e)}</td>
            <td class="px-4 py-2.5">
              <span class="rounded px-1.5 py-0.5 text-xs font-medium {statusBadge[st]}">{st}</span>
            </td>
            <td class="whitespace-nowrap px-4 py-2.5 text-gray-500">
              {e.completed_ms ? formatMS(e.completed_ms) : formatCreated(e.created)}
            </td>
            <td class="whitespace-nowrap px-4 py-2.5 text-right text-gray-500">{formatSize(e.size)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<svelte:window onkeydown={onKeydown} />

{#if openEntry}
  {@const e = openEntry}
  <div class="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto p-4 sm:p-8">
    <!-- Backdrop: a real button so click-to-close is keyboard/screen-reader accessible (Escape also closes). -->
    <button
      type="button"
      class="fixed inset-0 cursor-default bg-black/40"
      aria-label="Close details"
      tabindex="-1"
      onclick={() => (openId = null)}
    ></button>
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="queue-entry-title"
      class="relative my-4 w-full max-w-3xl rounded-xl border border-gray-200 bg-white shadow-lg"
    >
      <div class="flex items-center justify-between border-b border-gray-100 px-5 py-4">
        <h2 id="queue-entry-title" class="text-lg font-semibold text-gray-900">
          Queue entry #{e.id}
          <span class="ml-2 rounded px-1.5 py-0.5 align-middle text-xs font-medium {statusBadge[entryStatus(e)]}"
            >{entryStatus(e)}</span
          >
        </h2>
        <button
          type="button"
          class="rounded-lg p-1 text-gray-500 hover:bg-gray-100"
          onclick={() => (openId = null)}
          aria-label="Close"
        >
          <X class="size-5" />
        </button>
      </div>

      <dl class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 px-5 py-4 text-sm">
        <dt class="text-gray-500">From</dt>
        <dd class="break-all text-gray-900">{e.return_path || '<>'}</dd>
        <dt class="text-gray-500">Size</dt>
        <dd class="text-gray-900">{formatSize(e.size)} ({e.size} bytes)</dd>
        <dt class="text-gray-500">Created</dt>
        <dd class="text-gray-900">{formatCreated(e.created)}</dd>
        {#if e.completed_ms}
          <dt class="text-gray-500">Completed</dt>
          <dd class="text-gray-900">{formatMS(e.completed_ms)}</dd>
        {/if}
      </dl>

      <div class="overflow-x-auto border-t border-gray-100">
        <table class="min-w-full divide-y divide-gray-100 text-sm">
          <thead>
            <tr class="text-left text-xs text-gray-500">
              <th class="px-5 py-2 font-medium">Recipient</th>
              <th class="px-5 py-2 font-medium">Status</th>
              <th class="px-5 py-2 font-medium">Retry</th>
              <th class="px-5 py-2 font-medium">Next due</th>
              <th class="px-5 py-2 font-medium">Last attempt</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-50">
            {#each e.recipients as r (r.address)}
              <tr>
                <td class="px-5 py-2 font-medium break-all text-gray-900">{r.address}</td>
                <td class="px-5 py-2 text-gray-600">{r.status}</td>
                <td class="px-5 py-2 text-gray-600">{r.retry}</td>
                <td class="whitespace-nowrap px-5 py-2 text-gray-500">{formatMS(r.next_due_ms)}</td>
                <td class="whitespace-nowrap px-5 py-2 text-gray-500">{formatMS(r.last_attempt_ms)}</td>
              </tr>
              {#if r.last_diag}
                <tr>
                  <td
                    colspan="5"
                    class="px-5 pb-2 pt-0 font-mono text-xs break-all {r.status === 'delivered' ? 'text-gray-500' : 'text-red-700'}"
                  >
                    {r.last_diag}
                  </td>
                </tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>

      {#if tab === 'pending' && isAdmin}
        <div class="flex flex-wrap justify-end gap-2 border-t border-gray-100 px-5 py-4">
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
          <button type="button" class={btnClass(true)} disabled={busyId === e.id} onclick={() => (cancelTarget = e.id)}>
            Cancel
          </button>
        </div>
      {/if}
    </div>
  </div>
{/if}

{#if cancelTarget !== null}
  {@const id = cancelTarget}
  <ConfirmDialog
    title="Cancel queue entry #{id}"
    confirmLabel="Cancel delivery"
    danger
    busy={busyId === id}
    onconfirm={() =>
      void runAction(id, () => cancelQueueEntry(id)).then(() => {
        cancelTarget = null
        openId = null
      })}
    oncancel={() => (cancelTarget = null)}
  >
    <p>Pending recipients will not get this message, and no bounce is sent to the sender.</p>
  </ConfirmDialog>
{/if}
