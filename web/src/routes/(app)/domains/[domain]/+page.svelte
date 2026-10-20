<script lang="ts">
    import { KeyRound, MoreHorizontal, Pencil, Plus, Trash2, Users, X } from "@lucide/svelte";
    import ConfirmDialog from "$lib/ConfirmDialog.svelte";
    import { page } from "$app/state";
    import {
        ApiError,
        createAccount,
        deleteAccount,
        fetchAccounts,
        fetchDomain,
        fetchDnsRecommended,
        type DnsRecord,
        type Domain,
        type ListedAccount,
        type PatchDomainInput,
        patchAccount,
        patchDomain,
    } from "$lib/api";
    import { me } from "$lib/session";

    let accounts = $state<ListedAccount[]>([]);
    let domainInfo = $state<Domain | null>(null);
    let error = $state("");
    let loading = $state(true);
    let localPart = $state("");
    let password = $state("");
    let role = $state("user");
    let busy = $state(false);
    let dnsRecords = $state<DnsRecord[]>([]);
    let dnsError = $state("");
    let copiedKey = $state("");
    let formError = $state("");

    // Row actions menu, delete confirmation and password reset dialogs.
    let menuFor = $state<number | null>(null);
    let deleteTarget = $state<ListedAccount | null>(null);
    let deleteBusy = $state(false);
    let deleteError = $state("");
    let resetTarget = $state<ListedAccount | null>(null);
    let newPassword = $state("");
    let showPassword = $state(false);
    let resetBusy = $state(false);
    let resetError = $state("");

    let editOpen = $state(false);
    let editBusy = $state(false);
    let editError = $state("");
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

    const domain = $derived(page.params.domain ?? "");
    const canWrite = $derived($me?.role === "admin" || $me?.role === "tenant_admin");
    const roleOptions = $derived(
        $me?.role === "admin" ? ["user", "tenant_admin", "admin"] : ["user", "tenant_admin"],
    );

    function storageToBytes(amount: string, unit: "MB" | "GB"): number | undefined {
        const n = Number(amount);
        if (!amount || !Number.isFinite(n) || n <= 0) return undefined;
        const mul = unit === "GB" ? 1024 * 1024 * 1024 : 1024 * 1024;
        return Math.round(n * mul);
    }

    function bytesToStorage(bytes: number | undefined): { amount: string; unit: "MB" | "GB" } {
        if (!bytes) return { amount: "", unit: "MB" };
        const gb = 1024 * 1024 * 1024;
        const mb = 1024 * 1024;
        if (bytes >= gb && bytes % gb === 0) return { amount: String(bytes / gb), unit: "GB" };
        if (bytes >= mb && bytes % mb === 0) return { amount: String(bytes / mb), unit: "MB" };
        return { amount: String(Math.round((bytes / mb) * 100) / 100), unit: "MB" };
    }

    async function reload(name: string) {
        loading = true;
        error = "";
        try {
            const [list, info] = await Promise.all([fetchAccounts(name), fetchDomain(name)]);
            accounts = list;
            domainInfo = info;
        } catch (e) {
            error = e instanceof ApiError ? e.message : "failed to load domain";
        } finally {
            loading = false;
        }
    }

    $effect(() => {
        const name = domain;
        if (!name) return;
        let cancelled = false;
        loading = true;
        error = "";
        dnsError = "";
        dnsRecords = [];
        void Promise.all([fetchAccounts(name), fetchDomain(name)])
            .then(([list, info]) => {
                if (!cancelled) {
                    accounts = list;
                    domainInfo = info;
                }
            })
            .catch((e) => {
                if (!cancelled) {
                    error = e instanceof ApiError ? e.message : "failed to load domain";
                }
            })
            .finally(() => {
                if (!cancelled) loading = false;
            });
        // DNS records load separately: a failure here must not blank accounts/domain.
        void fetchDnsRecommended(name)
            .then((dns) => {
                if (!cancelled) dnsRecords = dns;
            })
            .catch((e) => {
                if (!cancelled) {
                    dnsError = e instanceof ApiError ? e.message : "failed to load DNS records";
                }
            });
        return () => {
            cancelled = true;
        };
    });

    function openEdit() {
        if (!domainInfo) return;
        catchAll = domainInfo.catch_all ?? "";
        mailHostname = domainInfo.mail_hostname ?? "";
        sslMode = (domainInfo.ssl_mode as "none" | "custom" | "acme") || "none";
        certPem = "";
        keyPem = "";
        dkimEnabled = !!domainInfo.dkim_enabled;
        antispam = !!domainInfo.antispam;
        sendMax = domainInfo.send_max_messages ? String(domainInfo.send_max_messages) : "";
        sendWindow = domainInfo.send_window || "1h";
        const st = bytesToStorage(domainInfo.storage_bytes);
        storageAmount = st.amount;
        storageUnit = st.unit;
        messagesQuota = domainInfo.messages_quota ? String(domainInfo.messages_quota) : "";
        relayEnabled = !!(domainInfo.relay_host ?? "");
        relayHost = domainInfo.relay_host ?? "";
        relayUser = domainInfo.relay_user ?? "";
        relayPassword = "";
        relayStartTLS = domainInfo.relay_starttls ?? true;
        editError = "";
        editOpen = true;
    }

    function closeEdit() {
        if (editBusy) return;
        editOpen = false;
    }

    async function onSaveEdit(e: Event) {
        e.preventDefault();
        editError = "";
        editBusy = true;
        try {
            const input: PatchDomainInput = {
                catch_all: catchAll.trim() || undefined,
                mail_hostname: mailHostname.trim() || undefined,
                ssl_mode: sslMode,
                cert_pem: sslMode === "custom" && certPem.trim() ? certPem : undefined,
                key_pem: sslMode === "custom" && keyPem.trim() ? keyPem : undefined,
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
            domainInfo = await patchDomain(domain, input);
            editOpen = false;
        } catch (err) {
            editError = err instanceof ApiError ? err.message : "update failed";
        } finally {
            editBusy = false;
        }
    }

    async function onCreate(e: Event) {
        e.preventDefault();
        formError = "";
        busy = true;
        try {
            await createAccount(domain, localPart.trim(), password, role);
            localPart = "";
            password = "";
            role = "user";
            await reload(domain);
        } catch (err) {
            formError = err instanceof ApiError ? err.message : "create failed";
        } finally {
            busy = false;
        }
    }

    function onDelete(a: ListedAccount) {
        menuFor = null;
        if (a.email === $me?.email) {
            formError = "cannot delete own account";
            return;
        }
        formError = "";
        deleteError = "";
        deleteTarget = a;
    }

    async function confirmDelete() {
        if (!deleteTarget) return;
        deleteBusy = true;
        deleteError = "";
        try {
            await deleteAccount(deleteTarget.email);
            deleteTarget = null;
            await reload(domain);
        } catch (err) {
            deleteError = err instanceof ApiError ? err.message : "delete failed";
        } finally {
            deleteBusy = false;
        }
    }

    function formatBytes(n: number): string {
        if (n < 1024) return `${n} B`;
        if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
        if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
        return `${(n / 1024 ** 3).toFixed(2)} GB`;
    }

    // Fill ratio of the tighter limit (storage or messages), null when unlimited.
    function usageRatio(a: ListedAccount): number | null {
        const ratios: number[] = [];
        if (a.storage_limit > 0) ratios.push(a.storage_used / a.storage_limit);
        if (a.messages_limit > 0) ratios.push(a.messages_used / a.messages_limit);
        return ratios.length ? Math.max(...ratios) : null;
    }

    function usageBarClass(r: number): string {
        if (r >= 0.9) return "bg-red-500";
        if (r >= 0.75) return "bg-amber-500";
        return "bg-emerald-500";
    }

    async function onToggleActive(a: ListedAccount) {
        if (a.email === $me?.email && a.active) {
            formError = "cannot deactivate own account";
            return;
        }
        formError = "";
        try {
            await patchAccount(a.email, { active: !a.active });
            await reload(domain);
        } catch (err) {
            formError = err instanceof ApiError ? err.message : "update failed";
        }
    }

    async function onChangeRole(a: ListedAccount, next: string) {
        formError = "";
        try {
            await patchAccount(a.email, { role: next });
            await reload(domain);
        } catch (err) {
            formError = err instanceof ApiError ? err.message : "update failed";
        }
    }

    function onResetPassword(a: ListedAccount) {
        menuFor = null;
        if (a.email === $me?.email) {
            formError = "cannot reset own password here";
            return;
        }
        formError = "";
        resetError = "";
        newPassword = "";
        showPassword = false;
        resetTarget = a;
    }

    async function submitReset(ev: SubmitEvent) {
        ev.preventDefault();
        if (!resetTarget || !newPassword) return;
        resetBusy = true;
        resetError = "";
        try {
            await patchAccount(resetTarget.email, { password: newPassword });
            resetTarget = null;
            newPassword = "";
        } catch (err) {
            resetError = err instanceof ApiError ? err.message : "password reset failed";
        } finally {
            resetBusy = false;
        }
    }
    async function copyDnsValue(r: DnsRecord) {
        try {
            await navigator.clipboard.writeText(r.value);
            copiedKey = r.type + r.host;
            setTimeout(() => {
                if (copiedKey === r.type + r.host) copiedKey = "";
            }, 1500);
        } catch {
            /* clipboard unavailable */
        }
    }
</script>

<div class="mb-6 flex flex-wrap items-center justify-between gap-3">
    <div class="flex items-center gap-2">
        <Users class="size-5 text-gray-700" />
        <h1 class="text-xl font-semibold text-gray-900">Accounts · {domain}</h1>
    </div>
    {#if canWrite && domainInfo}
        <button
            type="button"
            onclick={openEdit}
            class="inline-flex items-center gap-1 rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm font-medium text-gray-800 hover:bg-gray-50"
        >
            <Pencil class="size-4" />
            Edit domain
        </button>
    {/if}
</div>

{#if domainInfo}
    <div class="mb-6 flex flex-wrap gap-2 text-xs">
        <span
            class="rounded px-2 py-1 font-medium uppercase tracking-wide {domainInfo.antispam_active
                ? 'bg-emerald-50 text-emerald-800'
                : 'bg-gray-100 text-gray-500'}">AS</span
        >
        <span
            class="rounded px-2 py-1 font-medium uppercase tracking-wide {domainInfo.dkim_active
                ? 'bg-emerald-50 text-emerald-800'
                : 'bg-gray-100 text-gray-500'}">DKIM</span
        >
        <span
            class="rounded px-2 py-1 font-medium uppercase tracking-wide {domainInfo.ssl_active
                ? 'bg-emerald-50 text-emerald-800'
                : 'bg-gray-100 text-gray-500'}">SSL</span
        >
        {#if domainInfo.catch_all}
            <span class="rounded bg-gray-100 px-2 py-1 text-gray-700"
                >catch-all: {domainInfo.catch_all}@{domain}</span
            >
        {/if}
        {#if domainInfo.dkim_dns_name && domainInfo.dkim_dns_value}
            <span
                class="max-w-full truncate rounded bg-gray-100 px-2 py-1 font-mono text-gray-600"
                title={domainInfo.dkim_dns_value}>DNS: {domainInfo.dkim_dns_name}</span
            >
        {/if}
    </div>
{/if}

{#if canWrite}
    <form
        class="mb-6 flex flex-wrap items-end gap-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
        onsubmit={onCreate}
    >
        <div>
            <label for="local" class="mb-1 block text-xs font-medium text-gray-600"
                >Local part</label
            >
            <input
                id="local"
                required
                bind:value={localPart}
                placeholder="alice"
                class="rounded-lg border-gray-200 px-3 py-2 text-sm focus:border-brand-600 focus:ring-brand-600/30"
            />
        </div>
        <div>
            <label for="pw" class="mb-1 block text-xs font-medium text-gray-600">Password</label>
            <input
                id="pw"
                type="password"
                required
                bind:value={password}
                class="rounded-lg border-gray-200 px-3 py-2 text-sm focus:border-brand-600 focus:ring-brand-600/30"
            />
        </div>
        <div>
            <label for="role" class="mb-1 block text-xs font-medium text-gray-600">Role</label>
            <select
                id="role"
                bind:value={role}
                class="rounded-lg border-gray-200 px-3 py-2 text-sm"
            >
                {#each roleOptions as r}
                    <option value={r}>{r}</option>
                {/each}
            </select>
        </div>
        <button
            type="submit"
            disabled={busy}
            class="inline-flex items-center gap-1 rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white hover:bg-brand-800 disabled:opacity-50"
        >
            <Plus class="size-4" />
            Add account
        </button>
    </form>
    {#if formError}
        <p class="mb-4 text-sm text-red-600">{formError}</p>
    {/if}
{/if}

{#if loading}
    <p class="text-sm text-gray-500">Loading…</p>
{:else if error}
    <p class="text-sm text-red-600">{error}</p>
{:else if accounts.length === 0}
    <p class="text-sm text-gray-500">No accounts on this domain.</p>
{:else}
    <div class="overflow-x-auto rounded-xl border border-gray-200 bg-white shadow-sm">
        <table class="min-w-full divide-y divide-gray-200 text-sm">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-3 text-left font-medium text-gray-600">Email</th>
                    <th class="px-4 py-3 text-left font-medium text-gray-600">Role</th>
                    <th class="px-4 py-3 text-left font-medium text-gray-600">Usage</th>
                    <th class="px-4 py-3 text-left font-medium text-gray-600">Active</th>
                    {#if canWrite}
                        <th class="px-4 py-3 text-right font-medium text-gray-600">Actions</th>
                    {/if}
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
                {#each accounts as a (a.id)}
                    {@const ratio = usageRatio(a)}
                    <tr class="hover:bg-gray-50">
                        <td class="px-4 py-3 font-medium text-gray-900">{a.email}</td>
                        <td class="px-4 py-3 text-gray-600">
                            {#if canWrite}
                                <select
                                    class="rounded border-gray-200 px-2 py-1 text-sm"
                                    value={a.role}
                                    onchange={(e) => onChangeRole(a, e.currentTarget.value)}
                                >
                                    {#each roleOptions as r}
                                        <option value={r}>{r}</option>
                                    {/each}
                                </select>
                            {:else}
                                {a.role}
                            {/if}
                        </td>
                        <td class="px-4 py-3">
                            <div class="min-w-36 text-xs text-gray-700">
                                <span class="font-medium">{formatBytes(a.storage_used)}</span>
                                <span class="text-gray-500">
                                    / {a.storage_limit > 0 ? formatBytes(a.storage_limit) : "unlimited"}
                                </span>
                            </div>
                            {#if ratio !== null}
                                <div
                                    class="mt-1 h-1.5 w-36 overflow-hidden rounded-full bg-gray-100"
                                    role="progressbar"
                                    aria-label="Mailbox usage {a.email}"
                                    aria-valuemin={0}
                                    aria-valuemax={100}
                                    aria-valuenow={Math.round(Math.min(ratio, 1) * 100)}
                                >
                                    <div
                                        class="h-full {usageBarClass(ratio)}"
                                        style="width: {Math.min(ratio, 1) * 100}%"
                                    ></div>
                                </div>
                            {/if}
                            <div class="mt-0.5 text-[11px] text-gray-500">
                                {a.messages_used.toLocaleString()} msgs{a.messages_limit > 0
                                    ? ` / ${a.messages_limit.toLocaleString()}`
                                    : ""}
                            </div>
                        </td>
                        <td class="px-4 py-3 text-gray-600">
                            {#if canWrite}
                                <button
                                    type="button"
                                    class="text-brand-700 hover:underline"
                                    onclick={() => onToggleActive(a)}
                                >
                                    {a.active ? "yes" : "no"}
                                </button>
                            {:else}
                                {a.active ? "yes" : "no"}
                            {/if}
                        </td>
                        {#if canWrite}
                            <td class="relative px-4 py-3 text-right">
                                <button
                                    type="button"
                                    class="rounded-lg p-1.5 text-gray-500 hover:bg-gray-100"
                                    aria-label="Actions for {a.email}"
                                    aria-haspopup="menu"
                                    aria-expanded={menuFor === a.id}
                                    onclick={() => (menuFor = menuFor === a.id ? null : a.id)}
                                >
                                    <MoreHorizontal class="size-4" />
                                </button>
                                {#if menuFor === a.id}
                                    <div
                                        role="menu"
                                        class="absolute right-4 z-30 mt-1 w-44 overflow-hidden rounded-lg border border-gray-200 bg-white py-1 text-left shadow-lg"
                                    >
                                        <button
                                            type="button"
                                            role="menuitem"
                                            class="flex w-full items-center gap-2 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50"
                                            onclick={() => onResetPassword(a)}
                                        >
                                            <KeyRound class="size-4" /> Reset password
                                        </button>
                                        <button
                                            type="button"
                                            role="menuitem"
                                            class="flex w-full items-center gap-2 px-3 py-2 text-sm text-red-700 hover:bg-red-50"
                                            onclick={() => onDelete(a)}
                                        >
                                            <Trash2 class="size-4" /> Delete
                                        </button>
                                    </div>
                                {/if}
                            </td>
                        {/if}
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/if}

{#if dnsError}
    <h2 class="mb-3 mt-8 text-lg font-semibold text-gray-900">Recommended DNS records</h2>
    <p class="text-sm text-red-600">{dnsError}</p>
{:else if dnsRecords.length > 0}
    <h2 class="mb-3 mt-8 text-lg font-semibold text-gray-900">Recommended DNS records</h2>
    <div class="overflow-x-auto rounded-xl border border-gray-200 bg-white shadow-sm">
        <table class="min-w-full divide-y divide-gray-200 text-sm">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-3 text-left font-medium text-gray-600">Type</th>
                    <th class="px-4 py-3 text-left font-medium text-gray-600">Host</th>
                    <th class="px-4 py-3 text-left font-medium text-gray-600">Value</th>
                    <th class="px-4 py-3 text-right font-medium text-gray-600"></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
                {#each dnsRecords as r (r.type + r.host)}
                    <tr class="hover:bg-gray-50">
                        <td class="px-4 py-3 font-medium text-gray-900">{r.type}</td>
                        <td class="px-4 py-3 font-mono text-xs text-gray-600">{r.host}</td>
                        <td class="px-4 py-3 font-mono text-xs text-gray-600">
                            <span class="break-all">{r.value}</span>
                            {#if r.placeholder}
                                <span
                                    class="ml-2 rounded bg-amber-100 px-1.5 py-0.5 text-amber-800"
                                    title={r.note}>placeholder</span
                                >
                            {/if}
                            {#if r.note}
                                <p class="mt-1 text-xs text-gray-400">{r.note}</p>
                            {/if}
                        </td>
                        <td class="px-4 py-3 text-right">
                            <button
                                type="button"
                                class="text-xs text-brand-700 hover:underline"
                                onclick={() => copyDnsValue(r)}
                            >
                                {copiedKey === r.type + r.host ? "Copied!" : "Copy"}
                            </button>
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/if}

{#if editOpen}
    <div
        class="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/40 p-4 sm:p-8"
    >
        <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="edit-domain-title"
            class="my-4 w-full max-w-2xl rounded-xl border border-gray-200 bg-white shadow-lg"
        >
            <div class="flex items-center justify-between border-b border-gray-100 px-5 py-4">
                <h2 id="edit-domain-title" class="text-lg font-semibold text-gray-900">
                    Edit {domain}
                </h2>
                <button
                    type="button"
                    class="rounded-lg p-1 text-gray-500 hover:bg-gray-100"
                    onclick={closeEdit}
                    aria-label="Close"
                >
                    <X class="size-5" />
                </button>
            </div>
            <form class="space-y-5 px-5 py-4" onsubmit={onSaveEdit}>
                <div class="grid gap-4 sm:grid-cols-2">
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
                        <p class="text-xs text-gray-500">
                            Leave PEM empty to keep the current certificate.
                        </p>
                        <div>
                            <label
                                for="cert-pem"
                                class="mb-1 block text-xs font-medium text-gray-600"
                                >Certificate PEM</label
                            >
                            <textarea
                                id="cert-pem"
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
                                rows="4"
                                bind:value={keyPem}
                                class="block w-full rounded-lg border-gray-200 font-mono text-xs focus:border-brand-600 focus:ring-brand-600/30"
                            ></textarea>
                        </div>
                    {/if}
                </fieldset>

                <fieldset class="grid gap-3 sm:grid-cols-2">
                    <legend
                        class="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500 sm:col-span-2"
                        >Services</legend
                    >
                    <label class="inline-flex items-center gap-2 text-sm">
                        <input type="checkbox" bind:checked={dkimEnabled} />
                        DKIM signing
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
                                    placeholder="leave blank to keep"
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

                {#if editError}
                    <p class="text-sm text-red-600">{editError}</p>
                {/if}

                <div class="flex justify-end gap-2 border-t border-gray-100 pt-4">
                    <button
                        type="button"
                        onclick={closeEdit}
                        class="rounded-lg px-3 py-2 text-sm text-gray-700 hover:bg-gray-100"
                        disabled={editBusy}
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        disabled={editBusy}
                        class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white hover:bg-brand-800 disabled:opacity-50"
                    >
                        {editBusy ? "Saving…" : "Save changes"}
                    </button>
                </div>
            </form>
        </div>
    </div>
{/if}

<svelte:window
    onkeydown={(ev) => {
        if (ev.key === "Escape") menuFor = null;
    }}
    onclick={(ev) => {
        // Close the row menu on any click outside its toggle and items.
        if (menuFor !== null && !(ev.target as Element).closest('[role="menu"], [aria-haspopup="menu"]')) {
            menuFor = null;
        }
    }}
/>

{#if deleteTarget}
    <ConfirmDialog
        title="Delete mailbox"
        confirmLabel="Delete mailbox"
        danger
        requireText={deleteTarget.email}
        busy={deleteBusy}
        error={deleteError}
        onconfirm={confirmDelete}
        oncancel={() => (deleteTarget = null)}
    >
        <p>
            This permanently deletes <span class="font-medium">{deleteTarget.email}</span> and all its mail:
            <span class="font-medium">{deleteTarget.messages_used.toLocaleString()} messages</span>,
            <span class="font-medium">{formatBytes(deleteTarget.storage_used)}</span>.
        </p>
        <p class="text-red-700">This cannot be undone.</p>
    </ConfirmDialog>
{/if}

{#if resetTarget}
    <div class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:p-8">
        <button
            type="button"
            class="fixed inset-0 cursor-default bg-black/40"
            aria-label="Cancel"
            tabindex="-1"
            onclick={() => {
                if (!resetBusy) resetTarget = null;
            }}
        ></button>
        <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="reset-password-title"
            class="relative my-4 w-full max-w-md rounded-xl border border-gray-200 bg-white shadow-lg"
        >
            <div class="flex items-center justify-between border-b border-gray-100 px-5 py-4">
                <h2 id="reset-password-title" class="text-lg font-semibold text-gray-900">Reset password</h2>
                <button
                    type="button"
                    class="rounded-lg p-1 text-gray-500 hover:bg-gray-100"
                    onclick={() => (resetTarget = null)}
                    aria-label="Close"
                >
                    <X class="size-5" />
                </button>
            </div>
            <form class="space-y-4 px-5 py-4" onsubmit={submitReset}>
                <p class="text-sm text-gray-700">
                    New password for <span class="font-medium">{resetTarget.email}</span>.
                </p>
                <label class="block text-sm">
                    <span class="mb-1 block text-gray-600">New password</span>
                    <input
                        class="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm"
                        type={showPassword ? "text" : "password"}
                        autocomplete="new-password"
                        required
                        bind:value={newPassword}
                    />
                </label>
                <label class="flex items-center gap-2 text-xs text-gray-600">
                    <input type="checkbox" bind:checked={showPassword} /> Show password
                </label>
                {#if resetError}
                    <p class="text-sm text-red-600">{resetError}</p>
                {/if}
                <div class="flex justify-end gap-2 border-t border-gray-100 pt-4">
                    <button
                        type="button"
                        class="rounded-lg px-3 py-2 text-sm text-gray-700 hover:bg-gray-100"
                        disabled={resetBusy}
                        onclick={() => (resetTarget = null)}
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        disabled={resetBusy || !newPassword}
                        class="rounded-lg bg-brand-700 px-3 py-2 text-sm font-medium text-white hover:bg-brand-800 disabled:opacity-50"
                    >
                        {resetBusy ? "Saving…" : "Set password"}
                    </button>
                </div>
            </form>
        </div>
    </div>
{/if}
