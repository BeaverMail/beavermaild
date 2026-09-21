<script lang="ts">
import './layout.css'
import { onMount } from 'svelte'
import { afterNavigate } from '$app/navigation'
import { page } from '$app/state'
import favicon from '$lib/assets/beavermail.svg'
import { enforceSetupPath } from '$lib/setup'

let { children } = $props()

async function runSetupGuard() {
  await enforceSetupPath(page.url.pathname)
}

// Initialize Preline interactive helpers after mount (and on client navigations).
onMount(() => {
  void runSetupGuard()
  void import('preline').then(() => {
    const w = window as unknown as { HSStaticMethods?: { autoInit: () => void } }
    w.HSStaticMethods?.autoInit()
  })
})

afterNavigate(() => {
  void runSetupGuard()
})
</script>

<svelte:head>
  <title>BeaverMail Admin</title>
  <link rel="icon" href={favicon}>
</svelte:head>

{@render children()}
