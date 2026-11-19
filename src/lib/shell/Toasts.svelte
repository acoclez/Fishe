<script lang="ts">
  /** Transient notices (error, warnings, "recording saved") float above the page instead of pushing it down. */
  import { monitor } from "$lib/stores/monitor.svelte";
  import { session } from "$lib/stores/session.svelte";
</script>

<div class="toasts" aria-live="polite">
  {#if monitor.error}
    <div class="banner error" role="alert">
      <span>{monitor.error}</span>
      <button type="button" onclick={() => monitor.dismissError()} aria-label="Dismiss">×</button>
    </div>
  {/if}
  {#each monitor.warnings as w, i (i)}
    <div class="banner warn" role="status">
      <span>{w}</span>
      <button type="button" onclick={() => monitor.dismissWarning(i)} aria-label="Dismiss">×</button>
    </div>
  {/each}
  {#if monitor.lastSaved}
    <div class="banner saved" role="status">
      <span>Recording “<b>{monitor.lastSaved.name}</b>” saved to the archive.</span>
      <button type="button" class="open" onclick={() => session.openSaved()}>Open</button>
      <button type="button" onclick={() => monitor.dismissSaved()} aria-label="Dismiss">×</button>
    </div>
  {/if}
</div>

<style>
  .toasts {
    position: fixed;
    right: 18px;
    bottom: 18px;
    z-index: 50;
    display: flex;
    flex-direction: column;
    gap: 8px;
    width: min(440px, calc(100vw - 36px));
    pointer-events: none;
  }
  .banner {
    display: flex;
    gap: 10px;
    align-items: center;
    padding: 10px 14px;
    border-radius: var(--radius);
    font-size: 13px;
    pointer-events: auto;
    /* Opaque over whatever they float on: the tint sits on a solid surface. */
    background-color: var(--surface-2);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45);
  }
  .banner.error {
    border: 1px solid color-mix(in srgb, var(--danger) 45%, transparent);
    background-image: linear-gradient(var(--danger-wash), var(--danger-wash));
  }
  .banner.warn {
    border: 1px solid color-mix(in srgb, var(--level-busy) 40%, transparent);
    background-image: linear-gradient(
      color-mix(in srgb, var(--level-busy) 10%, transparent),
      color-mix(in srgb, var(--level-busy) 10%, transparent)
    );
    color: var(--text-secondary);
  }
  .banner.saved {
    border: 1px solid color-mix(in srgb, var(--accent) 45%, transparent);
    background-image: linear-gradient(var(--accent-wash), var(--accent-wash));
    color: var(--text-secondary);
  }
  .banner.saved b {
    color: var(--text-primary);
  }
  .banner button {
    margin-left: auto;
    border: 0;
    background: none;
    font-size: 18px;
    cursor: pointer;
    color: var(--text-secondary);
  }
  .banner .open {
    margin-left: auto;
    padding: 4px 12px;
    border-radius: 7px;
    border: 1px solid var(--accent);
    color: var(--accent-strong);
    font-size: 13px;
    font-weight: 600;
  }
  .banner .open + button {
    margin-left: 0;
  }
</style>
