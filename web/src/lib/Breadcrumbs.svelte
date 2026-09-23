<!-- Breadcrumb trail for (app) routes from the current path. -->
<script lang="ts">
import { ChevronRight } from '@lucide/svelte'
import { page } from '$app/state'

type Crumb = { label: string; href?: string }

const segmentLabel: Record<string, string> = {
  tenants: 'Tenants',
  domains: 'Domains',
  queue: 'Queue',
  delivery: 'Delivery test',
  status: 'Services',
  logs: 'Logs'
}

const crumbs = $derived.by((): Crumb[] => {
  const parts = page.url.pathname.split('/').filter(Boolean)
  if (parts.length === 0) return []
  const out: Crumb[] = []
  let path = ''
  for (let i = 0; i < parts.length; i++) {
    const seg = parts[i]
    path += `/${seg}`
    const label = segmentLabel[seg] ?? decodeURIComponent(seg)
    const last = i === parts.length - 1
    out.push(last ? { label } : { label, href: path })
  }
  return out
})
</script>

{#if crumbs.length > 0}
  <nav aria-label="Breadcrumb" class="mb-4">
    <ol class="flex flex-wrap items-center gap-1 text-sm text-gray-500">
      {#each crumbs as c, i (c.label + String(i))}
        {#if i > 0}
          <li aria-hidden="true" class="inline-flex text-gray-300">
            <ChevronRight class="size-3.5" />
          </li>
        {/if}
        <li class="inline-flex min-w-0">
          {#if c.href}
            <a class="truncate text-brand-700 hover:underline" href={c.href}>{c.label}</a>
          {:else}
            <span class="truncate font-medium text-gray-900" aria-current="page">{c.label}</span>
          {/if}
        </li>
      {/each}
    </ol>
  </nav>
{/if}
