<script lang="ts">
  /** Connections: programs (all-traffic mode), then the endpoints table or the packet list. */
  import EmptyState from "#lib/components/EmptyState.svelte";
  import EndpointsPanel from "#lib/pages/connections/EndpointsPanel.svelte";
  import FocusBar from "#lib/components/FocusBar.svelte";
  import PacketList from "#lib/pages/connections/PacketList.svelte";
  import ProgramsPanel from "#lib/pages/connections/ProgramsPanel.svelte";
  import { monitor } from "#lib/stores/monitor.svelte.ts";
  import { session } from "#lib/stores/session.svelte.ts";
  import { settings } from "#lib/stores/settings.svelte.ts";

  const s = $derived(monitor.latest);
</script>

{#if session.processMode && s?.endpoints && session.info}
  {#if monitor.active}<FocusBar />{/if}
  {#if session.allMode && s.programs}
    <ProgramsPanel rows={s.programs.rows} total={s.programs.total} nowMs={s.tMs} units={session.units} onmonitor={(name) => session.monitorProgram(name)} />
  {/if}
  <div class="view-switch" role="tablist" aria-label="Endpoints view">
    <button
      type="button"
      role="tab"
      aria-selected={settings.endpointsView !== "packets"}
      class:on={settings.endpointsView !== "packets"}
      onclick={() => (settings.endpointsView = "table")}>Endpoints</button
    >
    <button
      type="button"
      role="tab"
      aria-selected={settings.endpointsView === "packets"}
      class:on={settings.endpointsView === "packets"}
      onclick={() => (settings.endpointsView = "packets")}>Packets</button
    >
  </div>
  {#if settings.endpointsView === "packets"}
    <PacketList interfaces={session.info.interfaces} showPrograms={session.allMode} />
  {:else}
    <EndpointsPanel
      rows={monitor.endpointRows}
      total={Math.max(s.endpoints.total, monitor.endpointRows.length)}
      nowMs={s.tMs}
      units={session.units}
      showPrograms={session.allMode}
      program={session.programFilter}
      onclearprogram={() => monitor.setProgramFocus(null)}
    />
  {/if}
{:else}
  <EmptyState what="No connections to show" />
{/if}

<style>
  .view-switch {
    display: inline-flex;
    align-self: flex-start;
    padding: 3px;
    margin-bottom: -6px;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 9px;
  }
  .view-switch button {
    padding: 4px 16px;
    border: 0;
    border-radius: 6px;
    background: none;
    color: var(--text-secondary);
    font-weight: 600;
    font-size: 12px;
    cursor: pointer;
  }
  .view-switch button.on {
    background: var(--surface-3);
    color: var(--text-primary);
  }
</style>
