<script lang="ts">
    import { Server } from "@lucide/svelte";
    import { ApiError, type ServiceStatus, fetchServicesStatus } from "$lib/api";
    import { me } from "$lib/session";

    let services = $state<ServiceStatus[]>([]);
    let error = $state("");
    let loaded = $state(false);
    let refreshing = $state(false);

    const isAdmin = $derived($me?.role === "admin");

    async function load() {
        if (!isAdmin) return;
        refreshing = true;
        error = "";
        try {
            services = await fetchServicesStatus();
        } catch (e) {
            error = e instanceof ApiError ? e.message : "failed to load status";
        } finally {
            loaded = true;
            refreshing = false;
        }
    }

    $effect(() => {
        if (!isAdmin) return;
        void load();
    });

    function stateClass(state: string) {
        switch (state) {
            case "up":
                return "bg-green-100 text-green-800";
            case "error":
                return "bg-red-100 text-red-800";
            case "disabled":
                return "bg-gray-100 text-gray-600";
            default:
                return "bg-amber-100 text-amber-900";
        }
    }
</script>

<div class="mb-4 flex items-center justify-between gap-3">
    <div class="flex items-center gap-2">
        <Server class="size-5 text-gray-700" />
        <h1 class="text-xl font-semibold text-gray-900">Services</h1>
    </div>
    {#if isAdmin}
        <button
            type="button"
            class="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            disabled={refreshing}
            onclick={() => void load()}
        >
            {refreshing ? "Refreshing…" : "Refresh"}
        </button>
    {/if}
</div>

{#if !isAdmin}
    <p class="text-sm text-red-600">admin role required</p>
{:else if !loaded}
    <p class="text-sm text-gray-500">Loading…</p>
{:else}
    <p class="mb-6 max-w-xl text-sm text-gray-600">
        Listeners and background components: bind address and current state.
    </p>

    {#if error}
        <p class="mb-4 text-sm text-red-600">{error}</p>
    {/if}

    {#if services.length === 0}
        <p class="text-sm text-gray-500">No services reported.</p>
    {:else}
        <div class="overflow-x-auto rounded-xl border border-gray-200 bg-white">
            <table class="min-w-full text-left text-sm">
                <thead class="border-b border-gray-100 bg-gray-50 text-xs uppercase text-gray-500">
                    <tr>
                        <th class="px-4 py-3 font-medium">Service</th>
                        <th class="px-4 py-3 font-medium">Listen</th>
                        <th class="px-4 py-3 font-medium">State</th>
                        <th class="px-4 py-3 font-medium">Detail</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-100">
                    {#each services as svc (svc.id)}
                        <tr>
                            <td class="px-4 py-3 font-medium text-gray-900">{svc.name}</td>
                            <td class="px-4 py-3 font-mono text-xs text-gray-600"
                                >{svc.listen || "—"}</td
                            >
                            <td class="px-4 py-3">
                                <span
                                    class="rounded px-2 py-0.5 text-xs font-semibold {stateClass(
                                        svc.state,
                                    )}"
                                >
                                    {svc.state}
                                </span>
                            </td>
                            <td class="px-4 py-3 text-gray-500">{svc.error || ""}</td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        </div>
    {/if}
{/if}
