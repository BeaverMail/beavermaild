<script lang="ts">
import { Building2, Plus, Trash2 } from '@lucide/svelte'
import { onMount } from 'svelte'
import { ApiError, createTenant, deleteTenant, fetchTenants, patchTenant, type Tenant } from '$lib/api'
import ConfirmDialog from '$lib/ConfirmDialog.svelte'
import { me } from '$lib/session'

let tenants = $state<Tenant[]>([])
let error = $state('')
let loading = $state(true)
let name = $state('')
let busy = $state(false)
let formError = $state('')

const isAdmin = $derived($me?.role === 'admin')
const canRename = $derived($me?.role === 'admin' || $me?.role === 'tenant_admin')

onMount(async () => {
  try {
    tenants = await fetchTenants()
  } catch (e) {
    error = e instanceof ApiError ? e.message : 'failed to load tenants'
  } finally {
    loading = false
  }
})

async function reload() {
  tenants = await fetchTenants()
}

async function onCreate(e: Event) {
  e.preventDefault()
  formError = ''
  busy = true
  try {
    await createTenant(name.trim())
    name = ''
    await reload()
  } catch (err) {
    formError = err instanceof ApiError ? err.message : 'create failed'
  } finally {
    busy = false
  }
}

async function onRename(t: Tenant) {
  if (!canRenameOwn(t)) return
  const next = window.prompt('New tenant name:', t.name)
  if (next === null || next.trim() === '' || next.trim() === t.name) return
  formError = ''
  try {
    await patchTenant(t.id, next.trim())
    await reload()
  } catch (err) {
    formError = err instanceof ApiError ? err.message : 'rename failed'
  }
}

let deleteTarget = $state<Tenant | null>(null)
let deleteBusy = $state(false)
let deleteError = $state('')

function onDelete(t: Tenant) {
  if (!isAdmin || t.id === 1) return
  formError = ''
  deleteError = ''
  deleteTarget = t
}

async function confirmDelete() {
  const t = deleteTarget
  if (!t) return
  deleteBusy = true
  deleteError = ''
  try {
    await deleteTenant(t.id, t.name)
    deleteTarget = null
    await reload()
  } catch (err) {
    deleteError = err instanceof ApiError ? err.message : 'delete failed'
  } finally {
    deleteBusy = false
  }
}

function canRenameOwn(t: Tenant): boolean {
  if ($me?.role === 'admin') return true
  if ($me?.role === 'tenant_admin') return t.id === $me.tenant_id
  return false
}
</script>

<div class="mb-6 flex items-center gap-2">
  <Building2 class="size-5 text-gray-700" />
  <h1 class="text-xl font-semibold text-gray-900">Tenants</h1>
</div>

{#if isAdmin}
  <form
    class="mb-6 flex flex-wrap items-end gap-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    onsubmit={onCreate}
  >
    <div class="min-w-[12rem] flex-1">
      <label for="tenant-name" class="mb-1 block text-xs font-medium text-gray-600">Tenant name</label>
      <input
        id="tenant-name"
        required
        bind:value={name}
        placeholder="Acme"
        class="block w-full rounded-lg border-gray-200 px-3 py-2 text-sm focus:border-brand-600 focus:ring-brand-600/30"
      >
    </div>
    <button
      type="submit"
      disabled={busy}
      class="inline-flex items-center gap-1 rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white hover:bg-brand-800 disabled:opacity-50"
    >
      <Plus class="size-4" />
      Add tenant
    </button>
  </form>
{/if}

{#if formError}
  <p class="mb-4 text-sm text-red-600">{formError}</p>
{/if}

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
          {#if canRename}
            <th class="px-4 py-3 text-right font-medium text-gray-600">Actions</th>
          {/if}
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-100">
        {#each tenants as t (t.id)}
          <tr class="hover:bg-gray-50">
            <td class="px-4 py-3 text-gray-600">{t.id}</td>
            <td class="px-4 py-3 font-medium text-gray-900">{t.name}</td>
            {#if canRename}
              <td class="space-x-2 px-4 py-3 text-right">
                {#if canRenameOwn(t)}
                  <button type="button" class="text-xs text-brand-700 hover:underline" onclick={() => onRename(t)}>
                    Rename
                  </button>
                {/if}
                {#if isAdmin && t.id !== 1}
                  <button
                    type="button"
                    class="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-red-700 hover:bg-red-50"
                    onclick={() => onDelete(t)}
                  >
                    <Trash2 class="size-3.5" />
                    Delete
                  </button>
                {/if}
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if deleteTarget}
  <ConfirmDialog
    title="Delete tenant"
    confirmLabel="Delete tenant"
    danger
    requireText={deleteTarget.name}
    busy={deleteBusy}
    error={deleteError}
    onconfirm={confirmDelete}
    oncancel={() => (deleteTarget = null)}
  >
    <p>
      This permanently deletes the tenant <span class="font-medium">{deleteTarget.name}</span> with all its domains,
      accounts and mail.
    </p>
    <p class="text-red-700">This cannot be undone.</p>
  </ConfirmDialog>
{/if}
