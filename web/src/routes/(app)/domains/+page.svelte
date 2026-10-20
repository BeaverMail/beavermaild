<script lang="ts">
    import { Globe, Plus, Trash2, X } from "@lucide/svelte";
    import { onMount } from "svelte";
    import {
        ApiError,
        createDomain,
        type CreateDomainInput,
        type Domain,
        deleteDomain,
        fetchDomains,
        fetchTenants,
        type Tenant,
    } from "$lib/api";
    import { me } from "$lib/session";
    import ConfirmDialog from "$lib/ConfirmDialog.svelte";

    let domains = $state<Domain[]>([]);
    let tenants = $state<Tenant[]>([]);
    let error = $state("");
    let loading = $state(true);
    let modalOpen = $state(false);
    let busy = $state(false);
    let formError = $state("");

    let name = $state("");
    let tenantId = $state(1);
    let catchAll = $state("");
    let mailHostname = $state("");
    let sslMode = $state<"none" | "custom" | "acme">("none");
    let certPem = $state("");
    let keyPem = $state("");
    let dkimEnabled = $state(true);
    let antispam = $state(true);
    let sendMax = $state("");
    let sendWindow = $state("1h");
    let storageAmount = $state("");
    let storageUnit = $state<"MB" | "GB">("MB");
    let messagesQuota = $state("");
    let relayEnabled = $state(false);
    let relayHost = $state("");
    let relayUser = $state("");
    let relayPassword = $state("");
    let relayStartTLS = $state(true);

    const canWrite = $derived($me?.role === "admin" || $me?.role === "tenant_admin");
    const isAdmin = $derived($me?.role === "admin");
    const showTenantCol = $derived(isAdmin && tenants.length > 1);

    function tenantName(id: number): string {
        return tenants.find((t) => t.id === id)?.name ?? `#${id}`;
    }

    onMount(async () => {
        try {
            domains = await fetchDomains();
            if (isAdmin) {
                try {
                    tenants = await fetchTenants();
                    if (tenants.length > 0) tenantId = tenants[0].id;
                } catch {
                    /* tenants optional for listing domains */
                }
            }
        } catch (e) {
            error = e instanceof ApiError ? e.message : "failed to load domains";
        } finally {
            loading = false;
        }
    });

    function resetForm() {
        name = "";
        catchAll = "";
        mailHostname = "";
        sslMode = "none";
        certPem = "";
        keyPem = "";
        dkimEnabled = true;
        antispam = true;
        sendMax = "";
        sendWindow = "1h";
        storageAmount = "";
        storageUnit = "MB";
        messagesQuota = "";
        relayEnabled = false;
        relayHost = "";
        relayUser = "";
        relayPassword = "";
        relayStartTLS = true;
        formError = "";
        if (tenants.length > 0) tenantId = tenants[0].id;
    }

    function openModal() {
        resetForm();
        modalOpen = true;
    }

    function closeModal() {
        if (busy) return;
        modalOpen = false;
    }

    function formatBytes(n: number): string {
        if (!n) return "0 B";
        const units = ["B", "KB", "MB", "GB", "TB"];
        let v = n;
        let i = 0;
        while (v >= 1024 && i < units.length - 1) {
            v /= 1024;
            i++;
        }
        return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
    }

    function storageToBytes(amount: string, unit: "MB" | "GB"): number | undefined {
        const n = Number(amount);
        if (!amount || !Number.isFinite(n) || n <= 0) return undefined;
        const mul = unit === "GB" ? 1024 * 1024 * 1024 : 1024 * 1024;
        return Math.round(n * mul);
    }

    async function onCreate(e: Event) {
        e.preventDefault();
        formError = "";
        busy = true;
        try {
            const input: CreateDomainInput = {
                name: name.trim(),
                catch_all: catchAll.trim() || undefined,
                mail_hostname: mailHostname.trim() || undefined,
                ssl_mode: sslMode,
                cert_pem: sslMode === "custom" ? certPem : undefined,
                key_pem: sslMode === "custom" ? keyPem : undefined,
                dkim_enabled: dkimEnabled,
                antispam,
                send_max_messages: sendMax ? Number(sendMax) : undefined,
                send_window: sendMax ? sendWindow.trim() || undefined : undefined,
                storage_bytes: storageToBytes(storageAmount, storageUnit),
                messages_quota: messagesQuota ? Number(messagesQuota) : undefined,
                relay_host: relayEnabled ? relayHost.trim() || undefined : undefined,
                relay_user: relayEnabled ? relayUser.trim() || undefined : undefined,
                relay_password: relayEnabled ? relayPassword || undefined : undefined,
                relay_starttls: relayEnabled ? relayStartTLS : undefined,
            };
            if (isAdmin) input.tenant_id = Number(tenantId);
            const d = await createDomain(input);
            domains = [...domains.filter((x) => x.id !== d.id), d].sort((a, b) =>
                a.name.localeCompare(b.name),
            );
            modalOpen = false;
            resetForm();
        } catch (err) {
            formError = err instanceof ApiError ? err.message : "create failed";
        } finally {
            busy = false;
        }
    }

    let deleteTarget = $state<Domain | null>(null);
    let deleteBusy = $state(false);
    let deleteError = $state("");

    function onDelete(d: Domain) {
        formError = "";
        deleteError = "";
        deleteTarget = d;
    }

    async function confirmDelete() {
        const d = deleteTarget;
        if (!d) return;
        deleteBusy = true;
        deleteError = "";
        try {
            await deleteDomain(d.name);
            domains = domains.filter((x) => x.id !== d.id);
            deleteTarget = null;
        } catch (err) {
            deleteError = err instanceof ApiError ? err.message : "delete failed";
        } finally {
            deleteBusy = false;
        }
    }
</script>

<div class="mb-6 flex items-center justify-between gap-3">
    <div class="flex items-center gap-2">
        <Globe class="size-5 text-gray-700" />
        <h1 class="text-xl font-semibold text-gray-900">Domains</h1>
    </div>
    {#if canWrite}
        <button
            type="button"
            onclick={openModal}
            class="inline-flex items-center gap-1 rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white hover:bg-brand-800"
        >
            <Plus class="size-4" />
            Add domain
        </button>
    {/if}
</div>

{#if formError && !modalOpen}
    <p class="mb-4 text-sm text-red-600">{formError}</p>
{/if}

{#if loading}
    <p class="text-sm text-gray-500">Loading…</p>
{:else if error}
    <p class="text-sm text-red-600">{error}</p>
{:else if domains.length === 0}
    <p class="text-sm text-gray-500">No domains visible for this account.</p>
{:else}
    <div class="overflow-x-auto rounded-xl border border-gray-200 bg-white shadow-sm">
        <table class="min-w-full divide-y divide-gray-200 text-sm">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-3 text-left font-medium text-gray-600">Name</th>
                    <th class="px-4 py-3 text-left font-medium text-gray-600">Accounts</th>
                    <th class="px-4 py-3 text-left font-medium text-gray-600">Storage</th>
                    <th class="px-4 py-3 text-left font-medium text-gray-600">Services</th>
                    {#if showTenantCol}
                        <th class="px-4 py-3 text-left font-medium text-gray-600">Tenant</th>
                    {/if}
                    {#if canWrite}
                        <th class="px-4 py-3 text-right font-medium text-gray-600">Actions</th>
                    {/if}
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
                {#each domains as d (d.id)}
                    <tr class="hover:bg-gray-50">
                        <td class="px-4 py-3">
                            <a
                                class="font-medium text-brand-700 hover:underline"
                                href="/domains/{d.name}">{d.name}</a
                            >
                        </td>
                        <td class="px-4 py-3 text-gray-700">{d.account_count ?? 0}</td>
                        <td class="px-4 py-3 text-gray-600">{formatBytes(d.storage_used ?? 0)}</td>
                        <td class="px-4 py-3">
                            <div class="flex flex-wrap gap-1">
                                <span
                                    class="rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide {d.antispam_active
                                        ? 'bg-emerald-50 text-emerald-800'
                                        : 'bg-gray-100 text-gray-500'}">AS</span
                                >
                                <span
                                    class="rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide {d.dkim_active
                                        ? 'bg-emerald-50 text-emerald-800'
                                        : 'bg-gray-100 text-gray-500'}">DKIM</span
                                >
                                <span
                                    class="rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide {d.ssl_active
                                        ? 'bg-emerald-50 text-emerald-800'
                                        : 'bg-gray-100 text-gray-500'}">SSL</span
                                >
                            </div>
                        </td>
                        {#if showTenantCol}
                            <td class="px-4 py-3 text-gray-600">{tenantName(d.tenant_id)}</td>
                        {/if}
                        {#if canWrite}
                            <td class="px-4 py-3 text-right">
                                <button
                                    type="button"
                                    class="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-red-700 hover:bg-red-50"
                                    onclick={() => onDelete(d)}
                                >
                                    <Trash2 class="size-3.5" />
                                    Delete
                                </button>
                            </td>
                        {/if}
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/if}

{#if modalOpen}
    <div
        class="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/40 p-4 sm:p-8"
    >
        <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="create-domain-title"
            class="my-4 w-full max-w-2xl rounded-xl border border-gray-200 bg-white shadow-lg"
        >
            <div class="flex items-center justify-between border-b border-gray-100 px-5 py-4">
                <h2 id="create-domain-title" class="text-lg font-semibold text-gray-900">
                    Add domain
                </h2>
                <button
                    type="button"
                    class="rounded-lg p-1 text-gray-500 hover:bg-gray-100"
                    onclick={closeModal}
                    aria-label="Close"
                >
                    <X class="size-5" />
                </button>
            </div>
            <form class="space-y-5 px-5 py-4" onsubmit={onCreate}>
                <div class="grid gap-4 sm:grid-cols-2">
                    <div class="sm:col-span-2">
                        <label
                            for="domain-name"
                            class="mb-1 block text-xs font-medium text-gray-600">Domain name</label
                        >
                        <input
                            id="domain-name"
                            required
                            bind:value={name}
                            placeholder="example.com"
                            class="block w-full rounded-lg border-gray-200 px-3 py-2 text-sm focus:border-brand-600 focus:ring-brand-600/30"
                        />
                    </div>
                    {#if isAdmin && tenants.length > 1}
                        <div>
                            <label for="tenant" class="mb-1 block text-xs font-medium text-gray-600"
                                >Tenant</label
                            >
                            <select
                                id="tenant"
                                bind:value={tenantId}
                                class="w-full rounded-lg border-gray-200 px-3 py-2 text-sm"
                            >
                                {#each tenants as t (t.id)}
                                    <option value={t.id}>{t.name}</option>
                                {/each}
                            </select>
                        </div>
                    {/if}
                    <div>
                        <label for="catch-all" class="mb-1 block text-xs font-medium text-gray-600"
                            >Catch-all local-part</label
                        >
                        <input
                            id="catch-all"
                            bind:value={catchAll}
                            placeholder="postmaster (optional)"
                            class="block w-full rounded-lg border-gray-200 px-3 py-2 text-sm focus:border-brand-600 focus:ring-brand-600/30"
                        />
                    </div>
                    <div>
                        <label for="mail-host" class="mb-1 block text-xs font-medium text-gray-600"
                            >Mail hostname</label
                        >
                        <input
                            id="mail-host"
                            required
                            bind:value={mailHostname}
                            placeholder="mail.example.com"
                            class="block w-full rounded-lg border-gray-200 px-3 py-2 text-sm focus:border-brand-600 focus:ring-brand-600/30"
                        />
                    </div>
                </div>

                <fieldset class="space-y-3">
                    <legend class="text-xs font-semibold uppercase tracking-wide text-gray-500"
                        >SSL</legend
                    >
                    <div class="flex flex-wrap gap-4 text-sm">
                        <label class="inline-flex items-center gap-2">
                            <input type="radio" bind:group={sslMode} value="none" />
                            None
                        </label>
                        <label class="inline-flex items-center gap-2">
                            <input type="radio" bind:group={sslMode} value="acme" />
                            Let's Encrypt (HTTP-01)
                        </label>
                        <label class="inline-flex items-center gap-2">
                            <input type="radio" bind:group={sslMode} value="custom" />
                            Custom PEM
                        </label>
                    </div>
                    {#if sslMode === "custom"}
                        <div>
                            <label
                                for="cert-pem"
                                class="mb-1 block text-xs font-medium text-gray-600"
                                >Certificate PEM</label
                            >
                            <textarea
                                id="cert-pem"
                                required
                                rows="4"
                                bind:value={certPem}
                                class="block w-full rounded-lg border-gray-200 font-mono text-xs focus:border-brand-600 focus:ring-brand-600/30"
                            ></textarea>
                        </div>
                        <div>
                            <label
                                for="key-pem"
                                class="mb-1 block text-xs font-medium text-gray-600"
                                >Private key PEM</label
                            >
                            <textarea
                                id="key-pem"
                                required
                                rows="4"
                                bind:value={keyPem}
                                class="block w-full rounded-lg border-gray-200 font-mono text-xs focus:border-brand-600 focus:ring-brand-600/30"
                            ></textarea>
                        </div>
                    {/if}
                    {#if sslMode !== "none"}
                        <p class="text-xs text-gray-500">Mail hostname is required for SSL.</p>
                    {/if}
                </fieldset>

                <fieldset class="grid gap-3 sm:grid-cols-2">
                    <legend
                        class="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500 sm:col-span-2"
                        >Services</legend
                    >
                    <label class="inline-flex items-center gap-2 text-sm">
                        <input type="checkbox" bind:checked={dkimEnabled} />
                        Generate DKIM key
                    </label>
                    <label class="inline-flex items-center gap-2 text-sm">
                        <input type="checkbox" bind:checked={antispam} />
                        AntiSpam for this domain
                    </label>
                </fieldset>

                <fieldset class="grid gap-3 sm:grid-cols-2">
                    <legend
                        class="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500 sm:col-span-2"
                    >
                        Rate &amp; quota (optional overrides)
                    </legend>
                    <div>
                        <label for="send-max" class="mb-1 block text-xs font-medium text-gray-600"
                            >Send max messages</label
                        >
                        <input
                            id="send-max"
                            type="number"
                            min="0"
                            bind:value={sendMax}
                            placeholder="global default"
                            class="block w-full rounded-lg border-gray-200 px-3 py-2 text-sm"
                        />
                    </div>
                    <div>
                        <label
                            for="send-window"
                            class="mb-1 block text-xs font-medium text-gray-600">Send window</label
                        >
                        <input
                            id="send-window"
                            bind:value={sendWindow}
                            placeholder="1h"
                            class="block w-full rounded-lg border-gray-200 px-3 py-2 text-sm"
                        />
                    </div>
                    <div>
                        <label
                            for="storage-amount"
                            class="mb-1 block text-xs font-medium text-gray-600"
                            >Mailbox storage</label
                        >
                        <div class="flex gap-2">
                            <input
                                id="storage-amount"
                                type="number"
                                min="0"
                                step="any"
                                bind:value={storageAmount}
                                placeholder="global default"
                                class="block min-w-0 flex-1 rounded-lg border-gray-200 px-3 py-2 text-sm"
                            />
                            <select
                                aria-label="Storage unit"
                                bind:value={storageUnit}
                                class="appearance-none rounded-lg border-gray-200 px-3 py-2 text-sm"
                            >
                                <option value="MB">MB</option>
                                <option value="GB">GB</option>
                            </select>
                        </div>
                    </div>
                    <div>
                        <label
                            for="messages-quota"
                            class="mb-1 block text-xs font-medium text-gray-600"
                            >Mailbox message cap</label
                        >
                        <input
                            id="messages-quota"
                            type="number"
                            min="0"
                            bind:value={messagesQuota}
                            placeholder="global default"
                            class="block w-full rounded-lg border-gray-200 px-3 py-2 text-sm"
                        />
                    </div>
                </fieldset>

                <fieldset class="space-y-3">
                    <legend class="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500"
                        >SMTP relay</legend
                    >
                    <label class="inline-flex items-center gap-2 text-sm">
                        <input type="checkbox" bind:checked={relayEnabled} />
                        Use custom SMTP relay for this domain
                    </label>
                    {#if relayEnabled}
                        <div class="grid gap-3 sm:grid-cols-2">
                            <div class="sm:col-span-2">
                                <label
                                    for="relay-host"
                                    class="mb-1 block text-xs font-medium text-gray-600"
                                    >Relay host</label
                                >
                                <input
                                    id="relay-host"
                                    required
                                    bind:value={relayHost}
                                    placeholder="smtp.relay.example:587"
                                    class="block w-full rounded-lg border-gray-200 px-3 py-2 text-sm"
                                />
                            </div>
                            <div>
                                <label
                                    for="relay-user"
                                    class="mb-1 block text-xs font-medium text-gray-600"
                                    >Username</label
                                >
                                <input
                                    id="relay-user"
                                    bind:value={relayUser}
                                    class="block w-full rounded-lg border-gray-200 px-3 py-2 text-sm"
                                />
                            </div>
                            <div>
                                <label
                                    for="relay-pass"
                                    class="mb-1 block text-xs font-medium text-gray-600"
                                    >Password</label
                                >
                                <input
                                    id="relay-pass"
                                    type="password"
                                    bind:value={relayPassword}
                                    class="block w-full rounded-lg border-gray-200 px-3 py-2 text-sm"
                                />
                            </div>
                            <label class="inline-flex items-center gap-2 text-sm sm:col-span-2">
                                <input type="checkbox" bind:checked={relayStartTLS} />
                                STARTTLS
                            </label>
                        </div>
                    {/if}
                </fieldset>

                {#if formError}
                    <p class="text-sm text-red-600">{formError}</p>
                {/if}

                <div class="flex justify-end gap-2 border-t border-gray-100 pt-4">
                    <button
                        type="button"
                        onclick={closeModal}
                        class="rounded-lg px-3 py-2 text-sm text-gray-700 hover:bg-gray-100"
                        disabled={busy}
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        disabled={busy}
                        class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white hover:bg-brand-800 disabled:opacity-50"
                    >
                        {busy ? "Creating…" : "Create domain"}
                    </button>
                </div>
            </form>
        </div>
    </div>
{/if}

{#if deleteTarget}
    <ConfirmDialog
        title="Delete domain"
        confirmLabel="Delete domain"
        danger
        requireText={deleteTarget.name}
        busy={deleteBusy}
        error={deleteError}
        onconfirm={confirmDelete}
        oncancel={() => (deleteTarget = null)}
    >
        <p>
            This permanently deletes <span class="font-medium">{deleteTarget.name}</span>, its
            <span class="font-medium">{deleteTarget.account_count ?? 0} accounts</span> and all their mail.
        </p>
        <p class="text-red-700">This cannot be undone.</p>
    </ConfirmDialog>
{/if}
