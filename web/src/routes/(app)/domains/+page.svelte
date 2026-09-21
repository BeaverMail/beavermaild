<script lang="ts">
import { Globe, Plus, Trash2 } from '@lucide/svelte'
import { onMount } from 'svelte'
import { ApiError, createDomain, type Domain, deleteDomain, fetchDomains, fetchTenants, type Tenant } from '$lib/api'
import { me } from '$lib/session'

let domains = $state<Domain[]>([])
let tenants = $state<Tenant[]>([])
let error = $state('')
let loading = $state(true)
let name = $state('')
let tenantId = $state(1)
let busy = $state(false)
let formError = $state('')

const canWrite = $derived($me?.role === 'admin' || $me?.role === 'tenant_admin')
const isAdmin = $derived($me?.role === 'admin')

onMount(async () => {
  try {
    domains = await fetchDomains()
    if (isAdmin) {
      try {
        tenants = await fetchTenants()
        if (tenants.length > 0) tenantId = tenants[0].id
      } catch {
        /* tenants optional for listing domains */
      }
    }
  } catch (e) {
    error = e instanceof ApiError ? e.message : 'failed to load domains'
  } finally {
    loading = false
  }
})

async function onCreate(e: Event) {
  e.preventDefault()
  formError = ''
  busy = true
  try {
    const d = await createDomain(name.trim(), isAdmin ? Number(tenantId) : undefined)
    domains = [...domains.filter((x) => x.id !== d.id), d].sort((a, b) => a.name.localeCompare(b.name))
    name = ''
  } catch (err) {
    formError = err instanceof ApiError ? err.message : 'create failed'
  } finally {
    busy = false
  }
}

async function onDelete(d: Domain) {
  const confirmName = window.prompt(`Type ${d.name} to delete this domain and all accounts:`)
  if (confirmName !== d.name) return
  formError = ''
  try {
    await deleteDomain(d.name)
    domains = domains.filter((x) => x.id !== d.id)
  } catch (err) {
    formError = err instanceof ApiError ? err.message : 'delete failed'
  }
}
</script>

<div class="mb-6 flex items-center gap-2">
  <Globe class="size-5 text-gray-700" />
  <h1 class="text-xl font-semibold text-gray-900">Domains</h1>
</div>

{#if canWrite}
  <form
    class="mb-6 flex flex-wrap items-end gap-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    onsubmit={onCreate}
  >
    <div class="min-w-[12rem] flex-1">
      <label for="domain-name" class="mb-1 block text-xs font-medium text-gray-600">Domain name</label>
      <input
        id="domain-name"
        required
        bind:value={name}
        placeholder="example.com"
        class="block w-full rounded-lg border-gray-200 px-3 py-2 text-sm focus:border-brand-600 focus:ring-brand-600/30"
      >
    </div>
    {#if isAdmin && tenants.length > 0}
      <div>
        <label for="tenant" class="mb-1 block text-xs font-medium text-gray-600">Tenant</label>
        <select id="tenant" bind:value={tenantId} class="rounded-lg border-gray-200 px-3 py-2 text-sm">
          {#each tenants as t (t.id)}
            <option value={t.id}>{t.name} (#{t.id})</option>
          {/each}
        </select>
      </div>
    {/if}
    <button
      type="submit"
      disabled={busy}
      class="inline-flex items-center gap-1 rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white hover:bg-brand-800 disabled:opacity-50"
    >
      <Plus class="size-4" />
      Add domain
    </button>
  </form>
  {#if formError}
    <p class="mb-4 text-sm text-red-600">{formError}</p>
  {/if}
{/if}

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
          {#if canWrite}
            <th class="px-4 py-3 text-right font-medium text-gray-600">Actions</th>
          {/if}
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
            {#if canWrite}
              <td class="px-4 py-3 text-right">
                <button
                  type="button"
                  class="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-red-700 hover:bg-red-50"
                  onclick={() => onDelete(d)}
                >
                  <Trash2 class="size-3.5" />
                  Delete
                </button>
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
