<script lang="ts">
import { X } from '@lucide/svelte'
import type { Snippet } from 'svelte'

type Props = {
  title: string
  confirmLabel?: string
  /** Red confirm button for destructive actions. */
  danger?: boolean
  /** When set, the user must type this exact text before confirming. */
  requireText?: string
  busy?: boolean
  error?: string
  onconfirm: () => void
  oncancel: () => void
  children?: Snippet
}

let {
  title,
  confirmLabel = 'Confirm',
  danger = false,
  requireText = '',
  busy = false,
  error = '',
  onconfirm,
  oncancel,
  children
}: Props = $props()

let typed = $state('')
let input = $state<HTMLInputElement | null>(null)
let confirmButton = $state<HTMLButtonElement | null>(null)
const ready = $derived(!busy && (requireText === '' || typed === requireText))

// Focus the field to type into, or the confirm button, when the dialog opens.
$effect(() => {
  ;(input ?? confirmButton)?.focus()
})

function cancel() {
  if (!busy) oncancel()
}
</script>

<svelte:window
  onkeydown={(ev) => {
    if (ev.key === 'Escape') cancel()
  }}
/>

<div class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:p-8">
  <!-- Backdrop: a real button so click-to-cancel is accessible (Escape also cancels). -->
  <button
    type="button"
    class="fixed inset-0 cursor-default bg-black/40"
    aria-label="Cancel"
    tabindex="-1"
    onclick={cancel}
  ></button>
  <div
    role="alertdialog"
    aria-modal="true"
    aria-labelledby="confirm-dialog-title"
    class="relative my-4 w-full max-w-md rounded-xl border border-gray-200 bg-white shadow-lg"
  >
    <div class="flex items-center justify-between border-b border-gray-100 px-5 py-4">
      <h2 id="confirm-dialog-title" class="text-lg font-semibold text-gray-900">{title}</h2>
      <button type="button" class="rounded-lg p-1 text-gray-500 hover:bg-gray-100" onclick={cancel} aria-label="Close">
        <X class="size-5" />
      </button>
    </div>
    <form
      class="space-y-4 px-5 py-4"
      onsubmit={(ev) => {
        ev.preventDefault()
        if (ready) onconfirm()
      }}
    >
      {#if children}
        <div class="space-y-2 text-sm text-gray-700">{@render children()}</div>
      {/if}
      {#if requireText}
        <label class="block text-sm">
          <span class="mb-1 block text-gray-600">
            Type <span class="font-mono font-medium text-gray-900">{requireText}</span> to confirm
          </span>
          <input
            bind:this={input}
            bind:value={typed}
            class="w-full rounded-lg border border-gray-200 px-3 py-2 font-mono text-sm"
            autocomplete="off"
            spellcheck="false"
          >
        </label>
      {/if}
      {#if error}
        <p class="text-sm text-red-600">{error}</p>
      {/if}
      <div class="flex justify-end gap-2 border-t border-gray-100 pt-4">
        <button
          type="button"
          class="rounded-lg px-3 py-2 text-sm text-gray-700 hover:bg-gray-100"
          disabled={busy}
          onclick={cancel}
        >
          Cancel
        </button>
        <button
          bind:this={confirmButton}
          type="submit"
          disabled={!ready}
          class="rounded-lg px-3 py-2 text-sm font-medium text-white disabled:opacity-50 {danger
            ? 'bg-red-600 hover:bg-red-700'
            : 'bg-brand-700 hover:bg-brand-800'}"
        >
          {busy ? 'Working…' : confirmLabel}
        </button>
      </div>
    </form>
  </div>
</div>
