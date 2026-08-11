<script lang="ts">
import { Users } from '@lucide/svelte'
import { page } from '$app/state'
import { ApiError, fetchAccounts, type ListedAccount } from '$lib/api'

let accounts = $state<ListedAccount[]>([])
let error = $state('')
let loading = $state(true)

const domain = $derived(page.params.domain ?? '')

// Reload when the domain path param changes.
$effect(() => {
  const name = domain
  if (!name) return
  loading = true
  error = ''
  let cancelled = false
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
</script>

<div class="mb-2">
  <a class="text-sm text-brand-700 hover:underline" href="/domains">← Domains</a>
</div>

<div class="mb-6 flex items-center gap-2">
  <Users class="size-5 text-gray-700" />
  <h1 class="text-xl font-semibold text-gray-900">Accounts · {domain}</h1>
</div>

{#if loading}
  <p class="text-sm text-gray-500">Loading…</p>
{:else if error}
  <p class="text-sm text-red-600">{error}</p>
{:else if accounts.length === 0}
  <p class="text-sm text-gray-500">No accounts on this domain.</p>
{:else}
  <div class="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
    <table class="min-w-full divide-y divide-gray-200 text-sm">
      <thead class="bg-gray-50">
        <tr>
          <th class="px-4 py-3 text-left font-medium text-gray-600">Email</th>
          <th class="px-4 py-3 text-left font-medium text-gray-600">Role</th>
          <th class="px-4 py-3 text-left font-medium text-gray-600">Tenant</th>
          <th class="px-4 py-3 text-left font-medium text-gray-600">Active</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-100">
        {#each accounts as a (a.id)}
          <tr class="hover:bg-gray-50">
            <td class="px-4 py-3 font-medium text-gray-900">{a.email}</td>
            <td class="px-4 py-3 text-gray-600">{a.role}</td>
            <td class="px-4 py-3 text-gray-600">{a.tenant_id}</td>
            <td class="px-4 py-3 text-gray-600">{a.active ? 'yes' : 'no'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  <p class="mt-3 text-xs text-gray-400">Create account is not available yet (API write pending).</p>
{/if}
