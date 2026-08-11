<script lang="ts">
import { Globe } from '@lucide/svelte'
import { onMount } from 'svelte'
import { ApiError, type Domain, fetchDomains } from '$lib/api'

let domains = $state<Domain[]>([])
let error = $state('')
let loading = $state(true)

onMount(async () => {
  try {
    domains = await fetchDomains()
  } catch (e) {
    error = e instanceof ApiError ? e.message : 'failed to load domains'
  } finally {
    loading = false
  }
})
</script>

<div class="mb-6 flex items-center gap-2">
  <Globe class="size-5 text-gray-700" />
  <h1 class="text-xl font-semibold text-gray-900">Domains</h1>
</div>

{#if loading}
  <p class="text-sm text-gray-500">Loading…</p>
{:else if error}
  <p class="text-sm text-red-600">{error}</p>
{:else if domains.length === 0}
  <p class="text-sm text-gray-500">No domains visible for this account.</p>
{:else}
  <div class="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
    <table class="min-w-full divide-y divide-gray-200 text-sm">
      <thead class="bg-gray-50">
        <tr>
          <th class="px-4 py-3 text-left font-medium text-gray-600">Name</th>
          <th class="px-4 py-3 text-left font-medium text-gray-600">Tenant</th>
          <th class="px-4 py-3 text-left font-medium text-gray-600">ID</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-100">
        {#each domains as d (d.id)}
          <tr class="hover:bg-gray-50">
            <td class="px-4 py-3">
              <a class="font-medium text-brand-700 hover:underline" href="/domains/{d.name}">{d.name}</a>
            </td>
            <td class="px-4 py-3 text-gray-600">{d.tenant_id}</td>
            <td class="px-4 py-3 text-gray-500">{d.id}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  <p class="mt-3 text-xs text-gray-400">Create domain is not available yet (API write pending).</p>
{/if}
