<script lang="ts">
import { Building2 } from '@lucide/svelte'
import { onMount } from 'svelte'
import { ApiError, fetchTenants, type Tenant } from '$lib/api'

let tenants = $state<Tenant[]>([])
let error = $state('')
let loading = $state(true)

onMount(async () => {
  try {
    tenants = await fetchTenants()
  } catch (e) {
    error = e instanceof ApiError ? e.message : 'failed to load tenants'
  } finally {
    loading = false
  }
})
</script>

<div class="mb-6 flex items-center gap-2">
  <Building2 class="size-5 text-gray-700" />
  <h1 class="text-xl font-semibold text-gray-900">Tenants</h1>
</div>

{#if loading}
  <p class="text-sm text-gray-500">Loading…</p>
{:else if error}
  <p class="text-sm text-red-600">{error}</p>
{:else if tenants.length === 0}
  <p class="text-sm text-gray-500">No tenants visible.</p>
{:else}
  <div class="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
    <table class="min-w-full divide-y divide-gray-200 text-sm">
      <thead class="bg-gray-50">
        <tr>
          <th class="px-4 py-3 text-left font-medium text-gray-600">ID</th>
          <th class="px-4 py-3 text-left font-medium text-gray-600">Name</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-100">
        {#each tenants as t (t.id)}
          <tr class="hover:bg-gray-50">
            <td class="px-4 py-3 text-gray-600">{t.id}</td>
            <td class="px-4 py-3 font-medium text-gray-900">{t.name}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
