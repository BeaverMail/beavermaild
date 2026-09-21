<script lang="ts">
import { Plus, Trash2, Users } from '@lucide/svelte'
import { page } from '$app/state'
import { ApiError, createAccount, deleteAccount, fetchAccounts, type ListedAccount, patchAccount } from '$lib/api'
import { me } from '$lib/session'

let accounts = $state<ListedAccount[]>([])
let error = $state('')
let loading = $state(true)
let localPart = $state('')
let password = $state('')
let role = $state('user')
let busy = $state(false)
let formError = $state('')

const domain = $derived(page.params.domain ?? '')
const canWrite = $derived($me?.role === 'admin' || $me?.role === 'tenant_admin')
const roleOptions = $derived($me?.role === 'admin' ? ['user', 'tenant_admin', 'admin'] : ['user', 'tenant_admin'])

async function reload(name: string) {
  loading = true
  error = ''
  try {
    accounts = await fetchAccounts(name)
  } catch (e) {
    error = e instanceof ApiError ? e.message : 'failed to load accounts'
  } finally {
    loading = false
  }
}

$effect(() => {
  const name = domain
  if (!name) return
  let cancelled = false
  loading = true
  error = ''
  void fetchAccounts(name)
    .then((list) => {
      if (!cancelled) accounts = list
    })
    .catch((e) => {
      if (!cancelled) {
        error = e instanceof ApiError ? e.message : 'failed to load accounts'
      }
    })
    .finally(() => {
      if (!cancelled) loading = false
    })
  return () => {
    cancelled = true
  }
})

async function onCreate(e: Event) {
  e.preventDefault()
  formError = ''
  busy = true
  try {
    await createAccount(domain, localPart.trim(), password, role)
    localPart = ''
    password = ''
    role = 'user'
    await reload(domain)
  } catch (err) {
    formError = err instanceof ApiError ? err.message : 'create failed'
  } finally {
    busy = false
  }
}

async function onDelete(a: ListedAccount) {
  if (a.email === $me?.email) {
    formError = 'cannot delete own account'
    return
  }
  if (!window.confirm(`Delete ${a.email}?`)) return
  formError = ''
  try {
    await deleteAccount(a.email)
    await reload(domain)
  } catch (err) {
    formError = err instanceof ApiError ? err.message : 'delete failed'
  }
}

async function onToggleActive(a: ListedAccount) {
  if (a.email === $me?.email && a.active) {
    formError = 'cannot deactivate own account'
    return
  }
  formError = ''
  try {
    await patchAccount(a.email, { active: !a.active })
    await reload(domain)
  } catch (err) {
    formError = err instanceof ApiError ? err.message : 'update failed'
  }
}

async function onChangeRole(a: ListedAccount, next: string) {
  formError = ''
  try {
    await patchAccount(a.email, { role: next })
    await reload(domain)
  } catch (err) {
    formError = err instanceof ApiError ? err.message : 'update failed'
  }
}

async function onResetPassword(a: ListedAccount) {
  if (a.email === $me?.email) {
    formError = 'cannot reset own password here'
    return
  }
  const pw = window.prompt(`New password for ${a.email}:`)
  if (!pw) return
  formError = ''
  try {
    await patchAccount(a.email, { password: pw })
  } catch (err) {
    formError = err instanceof ApiError ? err.message : 'password reset failed'
  }
}
</script>

<div class="mb-6 flex items-center gap-2">
  <Users class="size-5 text-gray-700" />
  <h1 class="text-xl font-semibold text-gray-900">Accounts · {domain}</h1>
</div>

{#if canWrite}
  <form
    class="mb-6 flex flex-wrap items-end gap-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    onsubmit={onCreate}
  >
    <div>
      <label for="local" class="mb-1 block text-xs font-medium text-gray-600">Local part</label>
      <input
        id="local"
        required
        bind:value={localPart}
        placeholder="alice"
        class="rounded-lg border-gray-200 px-3 py-2 text-sm focus:border-brand-600 focus:ring-brand-600/30"
      >
    </div>
    <div>
      <label for="pw" class="mb-1 block text-xs font-medium text-gray-600">Password</label>
      <input
        id="pw"
        type="password"
        required
        bind:value={password}
        class="rounded-lg border-gray-200 px-3 py-2 text-sm focus:border-brand-600 focus:ring-brand-600/30"
      >
    </div>
    <div>
      <label for="role" class="mb-1 block text-xs font-medium text-gray-600">Role</label>
      <select id="role" bind:value={role} class="rounded-lg border-gray-200 px-3 py-2 text-sm">
        {#each roleOptions as r}
          <option value={r}>{r}</option>
        {/each}
      </select>
    </div>
    <button
      type="submit"
      disabled={busy}
      class="inline-flex items-center gap-1 rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white hover:bg-brand-800 disabled:opacity-50"
    >
      <Plus class="size-4" />
      Add account
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
{:else if accounts.length === 0}
  <p class="text-sm text-gray-500">No accounts on this domain.</p>
{:else}
  <div class="overflow-x-auto rounded-xl border border-gray-200 bg-white shadow-sm">
    <table class="min-w-full divide-y divide-gray-200 text-sm">
      <thead class="bg-gray-50">
        <tr>
          <th class="px-4 py-3 text-left font-medium text-gray-600">Email</th>
          <th class="px-4 py-3 text-left font-medium text-gray-600">Role</th>
          <th class="px-4 py-3 text-left font-medium text-gray-600">Active</th>
          {#if canWrite}
            <th class="px-4 py-3 text-right font-medium text-gray-600">Actions</th>
          {/if}
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-100">
        {#each accounts as a (a.id)}
          <tr class="hover:bg-gray-50">
            <td class="px-4 py-3 font-medium text-gray-900">{a.email}</td>
            <td class="px-4 py-3 text-gray-600">
              {#if canWrite}
                <select
                  class="rounded border-gray-200 px-2 py-1 text-sm"
                  value={a.role}
                  onchange={(e) => onChangeRole(a, e.currentTarget.value)}
                >
                  {#each roleOptions as r}
                    <option value={r}>{r}</option>
                  {/each}
                </select>
              {:else}
                {a.role}
              {/if}
            </td>
            <td class="px-4 py-3 text-gray-600">
              {#if canWrite}
                <button type="button" class="text-brand-700 hover:underline" onclick={() => onToggleActive(a)}>
                  {a.active ? 'yes' : 'no'}
                </button>
              {:else}
                {a.active ? 'yes' : 'no'}
              {/if}
            </td>
            {#if canWrite}
              <td class="px-4 py-3 text-right space-x-2">
                <button type="button" class="text-xs text-brand-700 hover:underline" onclick={() => onResetPassword(a)}>
                  Reset password
                </button>
                <button
                  type="button"
                  class="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-red-700 hover:bg-red-50"
                  onclick={() => onDelete(a)}
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
