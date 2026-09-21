<script lang="ts">
import { ListOrdered } from '@lucide/svelte'
import { onMount } from 'svelte'
import { ApiError, fetchQueue, type QueueEntry } from '$lib/api'
import { me } from '$lib/session'

let entries = $state<QueueEntry[]>([])
let error = $state('')
let loading = $state(true)
let showAll = $state(false)

const isAdmin = $derived($me?.role === 'admin')

async function reload() {
  loading = true
  error = ''
  try {
    entries = await fetchQueue(showAll)
  } catch (e) {
    error = e instanceof ApiError ? e.message : 'failed to load queue'
  } finally {
    loading = false
  }
}

onMount(() => {
  if (!isAdmin) {
    loading = false
    error = 'admin role required'
    return
  }
  void reload()
})

function formatMS(ms: number): string {
  if (!ms) return '—'
  return new Date(ms).toLocaleString()
}

function formatCreated(sec: number): string {
  if (!sec) return '—'
  // Queue Created is unix seconds in storage; tolerate ms if large.
  const ms = sec > 1e12 ? sec : sec * 1000
  return new Date(ms).toLocaleString()
}
</script>

<div class="mb-6 flex flex-wrap items-center justify-between gap-3">
  <div class="flex items-center gap-2">
    <ListOrdered class="size-5 text-gray-700" />
    <h1 class="text-xl font-semibold text-gray-900">Outbound queue</h1>
  </div>
  {#if isAdmin}
    <label class="inline-flex items-center gap-2 text-sm text-gray-600">
      <input type="checkbox" bind:checked={showAll} onchange={() => reload()} class="rounded border-gray-300">
      Include completed
    </label>
  {/if}
</div>

{#if loading}
  <p class="text-sm text-gray-500">Loading…</p>
{:else if error}
  <p class="text-sm text-red-600">{error}</p>
{:else if entries.length === 0}
  <p class="text-sm text-gray-500">No queue entries.</p>
{:else}
  <div class="space-y-4">
    {#each entries as e (e.id)}
      <div class="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
        <div class="flex flex-wrap gap-x-4 gap-y-1 border-b border-gray-100 bg-gray-50 px-4 py-3 text-sm">
          <span class="font-medium text-gray-900">#{e.id}</span>
          <span class="text-gray-600">from {e.return_path || '<>'}</span>
          <span class="text-gray-500">{e.size} bytes</span>
          <span class="text-gray-500">created {formatCreated(e.created)}</span>
          <span class="text-gray-500">pending {e.pending}</span>
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
            {/each}
          </tbody>
        </table>
      </div>
    {/each}
  </div>
{/if}
