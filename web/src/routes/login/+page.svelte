<script lang="ts">
import { goto } from '$app/navigation'
import { ApiError, login } from '$lib/api'
import logo from '$lib/assets/beavermail.svg'
import { me } from '$lib/session'

let email = $state('')
let password = $state('')
let error = $state('')
let busy = $state(false)

async function onSubmit(e: Event) {
  e.preventDefault()
  error = ''
  busy = true
  try {
    const account = await login(email.trim(), password)
    me.set(account)
    await goto('/domains')
  } catch (err) {
    error = err instanceof ApiError ? err.message : 'login failed'
  } finally {
    busy = false
  }
}
</script>

<!-- Preline auth card, light-first (no dark: flip from OS preference). -->
<main
  class="relative flex min-h-screen items-center justify-center px-4 py-12"
  style="background: linear-gradient(165deg, #faf6f3 0%, #f3ebe5 45%, #e5d3c6 100%)"
>
  <div class="relative w-full max-w-[26rem]">
    <div class="mb-8 text-center">
      <img src={logo} alt="" class="mx-auto mb-4 h-14 w-auto" width="112" height="80">
      <h1 class="text-3xl font-bold tracking-tight text-gray-900">BeaverMail</h1>
      <p class="mt-2 text-sm text-gray-500">Sign in to manage domains and accounts.</p>
    </div>

    <div class="rounded-xl border border-gray-200 bg-white shadow-sm">
      <div class="p-6 sm:p-8">
        <form onsubmit={onSubmit}>
          <div class="grid gap-y-5">
            {#if error}
              <div class="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" role="alert">
                {error}
              </div>
            {/if}

            <div>
              <label for="email" class="mb-2 block text-sm font-medium text-gray-800">Email address</label>
              <input
                type="email"
                id="email"
                name="email"
                autocomplete="username"
                required
                bind:value={email}
                class="block w-full rounded-lg border-gray-200 px-4 py-2.5 text-sm text-gray-900 placeholder:text-gray-400 focus:border-brand-600 focus:ring-brand-600/30 disabled:pointer-events-none disabled:opacity-50"
                placeholder="admin@example.com"
              >
            </div>

            <div>
              <label for="password" class="mb-2 block text-sm font-medium text-gray-800">Password</label>
              <input
                type="password"
                id="password"
                name="password"
                autocomplete="current-password"
                required
                bind:value={password}
                class="block w-full rounded-lg border-gray-200 px-4 py-2.5 text-sm text-gray-900 placeholder:text-gray-400 focus:border-brand-600 focus:ring-brand-600/30 disabled:pointer-events-none disabled:opacity-50"
                placeholder="••••••••"
              >
            </div>

            <button
              type="submit"
              disabled={busy}
              class="mt-1 inline-flex w-full items-center justify-center gap-x-2 rounded-lg border border-transparent bg-brand-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-brand-800 focus:bg-brand-800 focus:outline-hidden disabled:pointer-events-none disabled:opacity-50"
            >
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</main>
