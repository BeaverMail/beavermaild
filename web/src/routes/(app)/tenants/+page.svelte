<script lang="ts">
import { Building2, Gauge, Pencil, Plus, Trash2, X } from '@lucide/svelte'
import { onMount } from 'svelte'
import { ApiError, createTenant, deleteTenant, fetchTenants, patchTenant, type Tenant } from '$lib/api'
import { bytesToStorage, formatBytes, type StorageUnit, storageToBytes } from '$lib/bytes'
import ConfirmDialog from '$lib/ConfirmDialog.svelte'
import RowMenu, { type RowMenuItem } from '$lib/RowMenu.svelte'
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
    await patchTenant(t.id, { name: next.trim() })
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

// Storage quota, admin only: the tenant's mailboxes together cannot store more.
let capTarget = $state<Tenant | null>(null)
let capUnlimited = $state(true)
let capAmount = $state('')
let capUnit = $state<StorageUnit>('GB')
let capBusy = $state(false)
let capError = $state('')

function onEditCap(t: Tenant) {
  if (!isAdmin) return
  capError = ''
  capUnlimited = !t.storage_limit
  const st = bytesToStorage(t.storage_limit)
  capAmount = st.amount
  capUnit = t.storage_limit ? st.unit : 'GB'
  capTarget = t
}

async function submitCap(e: SubmitEvent) {
  e.preventDefault()
  const t = capTarget
  if (!t) return
  let limit = 0
  if (!capUnlimited) {
    const bytes = storageToBytes(capAmount, capUnit)
    if (bytes === undefined) {
      capError = 'Enter a quota above 0, or choose Unlimited.'
      return
    }
    limit = bytes
  }
  capBusy = true
  capError = ''
  try {
    await patchTenant(t.id, { storage_limit: limit })
    capTarget = null
    await reload()
  } catch (err) {
    capError = err instanceof ApiError ? err.message : 'update failed'
  } finally {
    capBusy = false
  }
}

// What this user may do on t: rename its own tenant, and (admin) set the quota or delete.
function tenantActions(t: Tenant): RowMenuItem[] {
  const out: RowMenuItem[] = []
  if (canRenameOwn(t)) out.push({ label: 'Rename', icon: Pencil, onselect: () => onRename(t) })
  if (isAdmin) out.push({ label: 'Storage quota', icon: Gauge, onselect: () => onEditCap(t) })
  if (isAdmin && t.id !== 1) out.push({ label: 'Delete', icon: Trash2, danger: true, onselect: () => onDelete(t) })
  return out
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
          <th class="px-4 py-3 text-left font-medium text-gray-600">Storage</th>
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
            <td class="px-4 py-3 text-xs text-gray-700 tabular-nums">
              <span class="font-medium">{formatBytes(t.storage_used)}</span>
              <span class="text-gray-500">/ {t.storage_limit ? formatBytes(t.storage_limit) : 'unlimited'}</span>
            </td>
            {#if canRename}
              <td class="px-4 py-3 text-right">
                {#if tenantActions(t).length}
                  <RowMenu label="Actions for {t.name}" items={tenantActions(t)} />
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

{#if capTarget}
  <div class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:p-8">
    <button
      type="button"
      class="fixed inset-0 cursor-default bg-black/40"
      aria-label="Cancel"
      tabindex="-1"
      onclick={() => {
        if (!capBusy) capTarget = null
      }}
    ></button>
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="cap-title"
      class="relative my-4 w-full max-w-md rounded-xl border border-gray-200 bg-white shadow-lg"
    >
      <div class="flex items-center justify-between border-b border-gray-100 px-5 py-4">
        <h2 id="cap-title" class="text-lg font-semibold text-gray-900">Storage quota</h2>
        <button
          type="button"
          class="rounded-lg p-1 text-gray-500 hover:bg-gray-100"
          onclick={() => (capTarget = null)}
          aria-label="Close"
        >
          <X class="size-5" />
        </button>
      </div>
      <form class="space-y-4 px-5 py-4" onsubmit={submitCap}>
        <p class="text-sm text-gray-700">
          All mailboxes of <span class="font-medium">{capTarget.name}</span> together, on top of each mailbox's own
          quota. In use now: {formatBytes(capTarget.storage_used)}.
        </p>
        <label class="flex items-center gap-2 text-sm text-gray-700">
          <input type="radio" name="cap-mode" value={true} bind:group={capUnlimited}>
          Unlimited
        </label>
        <label class="flex items-center gap-2 text-sm text-gray-700">
          <input type="radio" name="cap-mode" value={false} bind:group={capUnlimited}>
          Limit to
        </label>
        {#if !capUnlimited}
          <div class="ml-6 flex gap-2">
            <input
              type="number"
              min="0"
              step="any"
              aria-label="Storage quota"
              required
              bind:value={capAmount}
              class="block min-w-0 flex-1 rounded-lg border-gray-200 px-3 py-2 text-sm"
            >
            <select
              aria-label="Storage unit"
              bind:value={capUnit}
              class="appearance-none rounded-lg border-gray-200 py-2 pl-3 pr-9 text-sm"
            >
              <option value="MB">MB</option>
              <option value="GB">GB</option>
            </select>
          </div>
        {/if}
        {#if capError}
          <p class="text-sm text-red-600" role="alert">{capError}</p>
        {/if}
        <div class="flex justify-end gap-2 border-t border-gray-100 pt-4">
          <button
            type="button"
            class="rounded-lg px-3 py-2 text-sm text-gray-700 hover:bg-gray-100"
            disabled={capBusy}
            onclick={() => (capTarget = null)}
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={capBusy}
            class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white hover:bg-brand-800 disabled:opacity-50"
          >
            {capBusy ? 'Saving…' : 'Save quota'}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}

<svelte:window
  onkeydown={(ev) => {
    if (ev.key === 'Escape' && capTarget && !capBusy) capTarget = null
  }}
/>
