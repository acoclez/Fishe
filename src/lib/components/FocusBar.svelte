<script lang="ts">
  /**
   * Process / all-traffic mode: what the gauge, tiles and chart follow (the
   * whole session, one endpoint or one program) and a way back. Always
   * present at a fixed height, so focusing never moves the page.
   */
  import { monitor } from "$lib/stores/monitor.svelte";
  import { session } from "$lib/stores/session.svelte";

  const focusEp = $derived(session.focusEp);
  const focusProg = $derived(session.focusProg);
</script>

<div class="focus-bar" class:idle={!session.focus} role="status">
  <svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="5.5" /><circle cx="8" cy="8" r="1.8" class="dot" /></svg>
  {#if !session.focus}
    <span class="muted">Showing {session.wholeName}. Click {session.allMode ? "a program or an endpoint" : "an endpoint"} to focus the gauge, tiles and chart on it.</span>
  {:else if focusEp}
    <span>Focused on <b>{session.focusName}</b>{#if focusEp.name}<span class="mono muted ip">{focusEp.ip}</span>{/if}</span>
    <span class="muted">Gauge, tiles and chart show this endpoint only.</span>
    <button type="button" onclick={() => monitor.setFocus(null)}>{focusProg ? `Back to ${focusProg.name}` : `Show ${session.wholeName}`}</button>
  {:else if focusProg}
    <span>Focused on <b>{session.focusName}</b>{#if focusProg.pids.length}<span class="mono muted ip">{focusProg.pids.length === 1 ? `PID ${focusProg.pids[0]}` : `${focusProg.pids.length} processes`}</span>{/if}</span>
    <span class="muted">Gauge, tiles and chart show this program; endpoints are filtered to it.</span>
    <button type="button" onclick={() => monitor.setProgramFocus(null)}>Show {session.wholeName}</button>
  {/if}
</div>

<style>
  .focus-bar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 9px 14px;
    border-radius: var(--radius);
    background: var(--accent-wash);
    border: 1px solid color-mix(in srgb, var(--accent) 45%, transparent);
    font-size: 13px;
    /* One line, fixed height: its content changes, its size doesn't. */
    flex-wrap: nowrap;
    height: 42px;
    white-space: nowrap;
    overflow: hidden;
  }
  .focus-bar > span {
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .focus-bar.idle {
    background: var(--surface-1);
    border-color: var(--border);
  }
  .focus-bar.idle svg {
    stroke: var(--text-muted);
  }
  .focus-bar.idle .dot {
    fill: var(--text-muted);
  }
  .focus-bar svg {
    width: 16px;
    height: 16px;
    fill: none;
    stroke: var(--accent-strong);
    stroke-width: 1.6;
  }
  .focus-bar .dot {
    fill: var(--accent-strong);
    stroke: none;
  }
  .focus-bar button {
    margin-left: auto;
    padding: 5px 12px;
    border-radius: 8px;
    border: 1px solid var(--accent);
    background: none;
    color: var(--accent-strong);
    font-weight: 600;
    cursor: pointer;
  }
  .focus-bar button:hover {
    background: var(--accent-wash);
  }
  .focus-bar .ip {
    margin-left: 8px;
  }
</style>
