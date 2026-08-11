// Session account shared across admin routes (client SPA).
import { writable } from 'svelte/store'
import type { Account } from './api'

export const me = writable<Account | null>(null)
