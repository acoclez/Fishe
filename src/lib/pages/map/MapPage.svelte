<script lang="ts">
  /** Map: devices on the LAN, then the session's endpoints laid out by distance (or the host target's route). */
  import FocusBar from "#lib/components/FocusBar.svelte";
  import LanScan from "#lib/pages/map/LanScan.svelte";
  import NetworkMap from "#lib/pages/map/NetworkMap.svelte";
  import { monitor } from "#lib/stores/monitor.svelte.ts";
  import { session } from "#lib/stores/session.svelte.ts";

  const s = $derived(monitor.latest);
</script>

<section class="card map-card">
  <h2 class="card-title">Devices on your network</h2>
  <LanScan />
</section>
{#if session.processMode && s?.endpoints && session.info}
  {#if monitor.active}<FocusBar />{/if}
  <section class="card map-card">
    <h2 class="card-title">Traffic map{#if session.programFilter}<span class="scope-tag">· {session.programFilter.name}</span>{/if}</h2>
    <NetworkMap
      endpoints={session.mapEndpoints}
      units={session.units}
      focus={monitor.focus}
      onfocus={(ip) => monitor.setFocus(monitor.focus === ip ? null : ip)}
    />
  </section>
{:else if session.info?.mode === "host" && monitor.active && session.mapEndpoints.length}
  <section class="card map-card">
    <h2 class="card-title">Route</h2>
    <NetworkMap endpoints={session.mapEndpoints} units={session.units} focus={null} onfocus={() => {}} />
  </section>
{/if}

<style>
  .map-card {
    padding: 16px 18px 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .scope-tag {
    margin-left: 6px;
    color: var(--accent-strong);
    text-transform: none;
    letter-spacing: 0;
  }
</style>
