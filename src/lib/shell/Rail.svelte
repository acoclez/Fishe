<script lang="ts">
  /**
   * Side rail: one button per page, settings at the bottom. Fixed width; the
   * active marker moves with a transform, so nothing reflows.
   */
  import { PAGES, nav, type Page } from "#lib/stores/nav.svelte.ts";
  import Logo from "./Logo.svelte";

  let { live = false, recording = false }: { live?: boolean; recording?: boolean } = $props();

  const main = PAGES.filter((p) => p.id !== "settings");
  const settingsPage = PAGES.find((p) => p.id === "settings")!;
  const index = $derived(main.findIndex((p) => p.id === nav.page));
</script>

{#snippet icon(id: Page)}
  <svg viewBox="0 0 24 24" aria-hidden="true">
    {#if id === "live"}
      <path d="M4 15a8 8 0 0 1 16 0" /><path d="M12 15l4.5-5" /><circle cx="12" cy="15" r="1.4" class="fill" />
    {:else if id === "connections"}
      <path d="M4 6h16M4 12h16M4 18h10" />
    {:else if id === "map"}
      <circle cx="6" cy="17" r="2.2" /><circle cx="18" cy="7" r="2.2" /><circle cx="17" cy="17.5" r="1.6" /><path d="M7.8 15.6l8.4-7.2M8.2 17.2h7.2" />
    {:else if id === "archive"}
      <rect x="4" y="5" width="16" height="4" rx="1" /><path d="M5.5 9v9a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1V9M10 13h4" />
    {:else}
      <circle cx="12" cy="12" r="3" /><path d="M12 3.5v2.2M12 18.3v2.2M3.5 12h2.2M18.3 12h2.2M6 6l1.6 1.6M16.4 16.4L18 18M6 18l1.6-1.6M16.4 7.6L18 6" />
    {/if}
  </svg>
{/snippet}

<nav class="rail" aria-label="Pages">
  <div class="logo" title="Fishe"><Logo size={28} /></div>
  <div class="items">
    <i class="marker" class:hidden={index < 0} style:transform="translateY({Math.max(index, 0) * 60}px)" aria-hidden="true"></i>
    {#each main as p (p.id)}
      <button
        type="button"
        class:on={nav.page === p.id}
        aria-current={nav.page === p.id ? "page" : undefined}
        title="{p.label} ({p.key}): {p.hint}"
        onclick={() => nav.go(p.id)}
      >
        {@render icon(p.id)}
        <span>{p.label}</span>
        {#if p.id === "live" && (live || recording)}<b class="dot" class:rec={recording} aria-label={recording ? "recording" : "monitoring"}></b>{/if}
      </button>
    {/each}
  </div>
  <div class="foot">
    <button
      type="button"
      class:on={nav.page === "settings"}
      aria-current={nav.page === "settings" ? "page" : undefined}
      title="{settingsPage.label} ({settingsPage.key}): {settingsPage.hint}"
      onclick={() => nav.go("settings")}
    >
      {@render icon("settings")}
      <span>{settingsPage.label}</span>
    </button>
  </div>
</nav>

<style>
  .rail {
    width: 76px;
    flex: none;
    display: flex;
    flex-direction: column;
    align-items: stretch;
    padding: 12px 0 10px;
    border-right: 1px solid var(--border);
    background: linear-gradient(180deg, #0f1317, var(--bg));
  }
  .logo {
    display: flex;
    justify-content: center;
    height: 40px;
    margin-bottom: 14px;
  }
  .items {
    position: relative;
    display: flex;
    flex-direction: column;
  }
  .foot {
    margin-top: auto;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  button {
    position: relative;
    height: 60px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 4px;
    border: 0;
    background: none;
    color: var(--text-muted);
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.01em;
    cursor: pointer;
    transition: color 120ms ease;
  }
  button:hover {
    color: var(--text-primary);
  }
  button.on {
    color: var(--accent-strong);
  }
  button:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -4px;
    border-radius: 10px;
  }
  svg {
    width: 22px;
    height: 22px;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.6;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  svg .fill {
    fill: currentColor;
    stroke: none;
  }
  .marker {
    position: absolute;
    left: 0;
    top: 10px;
    width: 3px;
    height: 40px;
    border-radius: 0 3px 3px 0;
    background: var(--accent-strong);
    transition: transform 180ms cubic-bezier(0.3, 0.7, 0.3, 1), opacity 120ms;
    will-change: transform;
  }
  .marker.hidden {
    opacity: 0;
  }
  .dot {
    position: absolute;
    top: 12px;
    right: 22px;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--accent-strong);
  }
  .dot.rec {
    background: var(--danger);
  }
</style>
