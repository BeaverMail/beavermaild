<script lang="ts">
import { onMount } from 'svelte'
import { goto } from '$app/navigation'
import { ApiError, fetchMe } from '$lib/api'
import { me } from '$lib/session'

onMount(async () => {
  try {
    const account = await fetchMe()
    me.set(account)
    await goto('/domains')
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      await goto('/login')
      return
    }
    await goto('/login')
  }
})
</script>

<p class="p-8 text-sm text-gray-500">Loading…</p>
