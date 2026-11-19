<script lang="ts">
// Row actions menu. It is positioned fixed against the viewport, so a table wrapper with overflow
// (hidden or auto) cannot clip it; it opens upwards when there is no room below.
import { MoreHorizontal } from '@lucide/svelte'
import { tick } from 'svelte'

export type RowMenuItem = {
  label: string
  icon?: typeof MoreHorizontal
  danger?: boolean
  onselect: () => void
}

let { label, items }: { label: string; items: RowMenuItem[] } = $props()

let open = $state(false)
let top = $state(0)
let right = $state(0)
let button: HTMLButtonElement
let menu = $state<HTMLDivElement>()

function buttons(): HTMLButtonElement[] {
  return menu ? [...menu.querySelectorAll<HTMLButtonElement>('button')] : []
}

async function show() {
  const r = button.getBoundingClientRect()
  right = Math.max(8, window.innerWidth - r.right) // never past the screen edge
  top = r.bottom + 4
  open = true
  await tick()
  const h = menu?.offsetHeight ?? 0
  if (r.bottom + 4 + h > window.innerHeight - 8 && r.top - 4 - h >= 8) top = r.top - 4 - h
  buttons()[0]?.focus({ preventScroll: true })
}

function hide(refocus: boolean) {
  open = false
  if (refocus) button.focus()
}

function pick(item: RowMenuItem) {
  hide(false)
  item.onselect()
}

function onMenuKey(ev: KeyboardEvent) {
  const list = buttons()
  const i = list.indexOf(document.activeElement as HTMLButtonElement)
  if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
    ev.preventDefault()
    const step = ev.key === 'ArrowDown' ? 1 : -1
    list[(i + step + list.length) % list.length]?.focus({ preventScroll: true })
  } else if (ev.key === 'Home' || ev.key === 'End') {
    ev.preventDefault()
    list[ev.key === 'Home' ? 0 : list.length - 1]?.focus({ preventScroll: true })
  } else if (ev.key === 'Tab') {
    hide(false)
  }
}

// A fixed menu would drift from its row on scroll or resize: close it instead.
$effect(() => {
  if (!open) return
  const close = () => hide(false)
  const outside = (ev: MouseEvent) => {
    const t = ev.target as Node
    if (!menu?.contains(t) && !button.contains(t)) hide(false)
  }
  const onEscape = (ev: KeyboardEvent) => {
    if (ev.key === 'Escape') hide(true)
  }
  window.addEventListener('scroll', close, true)
  window.addEventListener('resize', close)
  document.addEventListener('mousedown', outside)
  document.addEventListener('keydown', onEscape)
  return () => {
    window.removeEventListener('scroll', close, true)
    window.removeEventListener('resize', close)
    document.removeEventListener('mousedown', outside)
    document.removeEventListener('keydown', onEscape)
  }
})
</script>

<button
  bind:this={button}
  type="button"
  class="rounded-lg p-1.5 text-gray-500 hover:bg-gray-100"
  aria-label={label}
  aria-haspopup="menu"
  aria-expanded={open}
  onclick={() => (open ? hide(true) : show())}
>
  <MoreHorizontal class="size-4" />
</button>
{#if open}
  <div
    bind:this={menu}
    role="menu"
    tabindex="-1"
    aria-label={label}
    class="fixed z-50 w-48 overflow-hidden rounded-lg border border-gray-200 bg-white py-1 text-left shadow-lg"
    style="top: {top}px; right: {right}px"
    onkeydown={onMenuKey}
  >
    {#each items as item (item.label)}
      <button
        type="button"
        role="menuitem"
        class="flex w-full items-center gap-2 px-3 py-2 text-sm focus:outline-none {item.danger
          ? 'text-red-700 hover:bg-red-50 focus:bg-red-50'
          : 'text-gray-700 hover:bg-gray-50 focus:bg-gray-50'}"
        onclick={() => pick(item)}
      >
        {#if item.icon}
          <item.icon class="size-4" />
        {/if}
        {item.label}
      </button>
    {/each}
  </div>
{/if}
