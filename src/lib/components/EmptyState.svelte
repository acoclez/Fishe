<script lang="ts">
  /** Connections and Map without a program / all-traffic session: say why, offer Live. */
  import { monitor } from "$lib/stores/monitor.svelte";
  import { nav } from "$lib/stores/nav.svelte";

  let { what }: { what: string } = $props();
</script>

<section class="card empty">
  <h2>{what}</h2>
  <p class="muted">
    {#if monitor.phase === "running"}
      This page needs a program or all-traffic session; the current one follows a single host.
    {:else}
      No session is running.
    {/if}
  </p>
  <button type="button" onclick={() => nav.go("live")}>Go to Live to start one</button>
</section>

<style>
  .empty {
    padding: 28px 24px;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }
  .empty h2 {
    margin: 0;
    font-size: 15px;
  }
  .empty p {
    margin: 0;
    font-size: 13px;
  }
  .empty button {
    margin-top: 6px;
    padding: 6px 14px;
    border-radius: 8px;
    border: 1px solid var(--accent);
    background: none;
    color: var(--accent-strong);
    font-weight: 600;
    cursor: pointer;
  }
</style>
