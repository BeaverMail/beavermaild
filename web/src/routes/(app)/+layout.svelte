<script lang="ts">
import { Building2, Globe, LogOut } from '@lucide/svelte'
import { onMount } from 'svelte'
import { goto } from '$app/navigation'
import { page } from '$app/state'
import { ApiError, fetchMe, logout } from '$lib/api'
import logo from '$lib/assets/beavermail.svg'
import { me } from '$lib/session'

let { children } = $props()
let ready = $state(false)
let loadError = $state('')

onMount(async () => {
  try {
    const account = await fetchMe()
    me.set(account)
    ready = true
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      await goto('/login')
      return
    }
    loadError = e instanceof Error ? e.message : 'failed to load session'
  }
})

async function onLogout() {
  await logout()
  me.set(null)
  await goto('/login')
}

function navClass(href: string) {
  const path = page.url.pathname
  const active = path === href || path.startsWith(`${href}/`)
  return active
    ? 'flex items-center gap-2 rounded-lg bg-brand-100 px-3 py-2 text-sm font-medium text-brand-900'
    : 'flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-gray-600 hover:bg-brand-50 hover:text-gray-900'
}
</script>

{#if loadError}
  <p class="p-8 text-sm text-red-600">{loadError}</p>
{:else if !ready}
  <p class="p-8 text-sm text-gray-500">Loading…</p>
{:else}
  <div class="min-h-screen md:flex">
    <aside class="border-b border-gray-200 bg-white md:w-56 md:shrink-0 md:border-b-0 md:border-r">
      <div class="flex items-center justify-between gap-2 px-4 py-4 md:block">
        <div>
          <div class="flex items-center gap-2">
            <img src={logo} alt="" class="h-7 w-auto shrink-0" width="40" height="28">
            <p class="text-sm font-semibold text-gray-900">BeaverMail</p>
          </div>
          {#if $me}
            <p class="mt-1 truncate text-xs text-gray-500">{$me.email}</p>
            <p class="text-xs text-gray-400">{$me.role}</p>
          {/if}
        </div>
        <button
          type="button"
          class="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-gray-600 hover:bg-gray-50 md:mt-3"
          onclick={onLogout}
        >
          <LogOut class="size-3.5" />
          Sign out
        </button>
      </div>
      <nav class="flex gap-1 px-2 pb-3 md:flex-col">
        {#if $me && ($me.role === 'admin' || $me.role === 'tenant_admin')}
          <a class={navClass('/tenants')} href="/tenants">
            <Building2 class="size-4" />
            Tenants
          </a>
        {/if}
        <a class={navClass('/domains')} href="/domains">
          <Globe class="size-4" />
          Domains
        </a>
      </nav>
    </aside>
    <main class="flex-1 p-4 md:p-8">
      {@render children()}
    </main>
  </div>
{/if}
