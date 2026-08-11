<script lang="ts">
import './layout.css'
import { onMount } from 'svelte'
import favicon from '$lib/assets/beavermail.svg'

let { children } = $props()

// Initialize Preline interactive helpers after mount (and on client navigations).
onMount(() => {
  void import('preline').then(() => {
    const w = window as unknown as { HSStaticMethods?: { autoInit: () => void } }
    w.HSStaticMethods?.autoInit()
  })
})
</script>

<svelte:head>
  <title>BeaverMail Admin</title>
  <link rel="icon" href={favicon}>
</svelte:head>

{@render children()}
