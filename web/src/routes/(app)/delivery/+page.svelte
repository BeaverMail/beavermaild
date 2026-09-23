<script lang="ts">
import { Activity } from '@lucide/svelte'
import { ApiError, type DeliveryProbeResult, fetchDeliveryStatus, runDeliveryTest } from '$lib/api'
import { me } from '$lib/session'

type Mode = 'auto' | 'mx' | 'relay'

let mode = $state<Mode>('mx')
let to = $state('')
let busy = $state(false)
let error = $state('')
let result = $state<DeliveryProbeResult | null>(null)
let relayConfigured = $state(false)
let relayHost = $state('')
let statusLoaded = $state(false)

const isAdmin = $derived($me?.role === 'admin')

$effect(() => {
  if (!isAdmin) return
  void (async () => {
    try {
      const st = await fetchDeliveryStatus()
      relayConfigured = st.relay_configured
      relayHost = st.relay || ''
      if (st.relay_configured) mode = 'auto'
      else if (mode === 'relay' || mode === 'auto') mode = 'mx'
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'failed to load delivery status'
    } finally {
      statusLoaded = true
    }
  })()
})

async function run() {
  if (!isAdmin) return
  if (mode === 'relay' && !relayConfigured) return
  busy = true
  error = ''
  result = null
  try {
    result = await runDeliveryTest({
      mode: relayConfigured ? mode : mode === 'auto' ? 'mx' : mode,
      to: to.trim() || undefined
    })
  } catch (e) {
    error = e instanceof ApiError ? e.message : 'delivery test failed'
  } finally {
    busy = false
  }
}
</script>

<div class="mb-4 flex items-center gap-2">
  <Activity class="size-5 text-gray-700" />
  <h1 class="text-xl font-semibold text-gray-900">Delivery test</h1>
</div>

{#if !isAdmin}
  <p class="text-sm text-red-600">admin role required</p>
{:else if !statusLoaded}
  <p class="text-sm text-gray-500">Loading…</p>
{:else}
  <p class="mb-6 max-w-xl text-sm text-gray-600">
    Probe outbound connectivity: dial, EHLO, STARTTLS/AUTH when applicable. No message is sent.
  </p>

  <form
    class="mb-8 flex max-w-xl flex-col gap-4"
    onsubmit={(e) => {
      e.preventDefault()
      void run()
    }}
  >
    <label class="block text-sm">
      <span class="mb-1 block font-medium text-gray-700">Mode</span>
      <select class="w-full rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm" bind:value={mode}>
        {#if relayConfigured}
          <option value="auto">Auto (relay if set, else MX)</option>
        {/if}
        <option value="mx">MX lookup</option>
        {#if relayConfigured}
          <option value="relay">Configured relay ({relayHost})</option>
        {/if}
      </select>
    </label>

    {#if mode !== 'relay'}
      <label class="block text-sm">
        <span class="mb-1 block font-medium text-gray-700">Recipient or domain</span>
        <input
          class="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm"
          type="text"
          placeholder="user@example.com or example.com"
          bind:value={to}
        >
      </label>
    {/if}

    <button
      type="submit"
      class="inline-flex w-fit items-center rounded-lg bg-brand-700 px-4 py-2 text-sm font-medium text-white hover:bg-brand-800 disabled:opacity-50"
      disabled={busy || (mode !== 'relay' && !to.trim())}
    >
      {busy ? 'Running…' : 'Run probe'}
    </button>
  </form>

  {#if error}
    <p class="mb-4 text-sm text-red-600">{error}</p>
  {/if}

  {#if result}
    <div class="max-w-2xl rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
      <div class="mb-3 flex flex-wrap items-center gap-3 text-sm">
        <span
          class="rounded px-2 py-0.5 text-xs font-semibold {result.ok
            ? 'bg-green-100 text-green-800'
            : 'bg-red-100 text-red-800'}"
        >
          {result.ok ? 'OK' : 'Failed'}
        </span>
        <span class="text-gray-600">mode {result.mode}</span>
        {#if result.domain}
          <span class="text-gray-500">{result.domain}</span>
        {/if}
        {#if result.host}
          <span class="font-mono text-xs text-gray-500">{result.host}</span>
        {/if}
      </div>
      <ol class="space-y-2 text-sm">
        {#each result.steps as step, i (i)}
          <li class="flex gap-2">
            <span class={step.ok ? 'text-green-700' : 'text-red-700'}>{step.ok ? '✓' : '✗'}</span>
            <span class="font-medium text-gray-900">{step.name}</span>
            {#if step.detail}
              <span class="text-gray-500">{step.detail}</span>
            {/if}
            {#if step.error}
              <span class="text-red-600">{step.error}</span>
            {/if}
          </li>
        {/each}
      </ol>
    </div>
  {/if}
{/if}
