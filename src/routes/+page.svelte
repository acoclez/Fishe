<script lang="ts">
  /**
   * The shell: rail, header, the page that is open, the toasts. What the pages
   * share lives in `session` (src/lib/stores/session.svelte.ts); what each page shows
   * lives in src/lib/pages/.
   */
  import { onMount, tick, untrack } from "svelte";
  import { api, inTauri } from "$lib/api";
  import ArchivePage from "$lib/pages/archive/ArchivePage.svelte";
  import HeaderStatus from "$lib/shell/HeaderStatus.svelte";
  import Rail from "$lib/shell/Rail.svelte";
  import SettingsPage from "$lib/pages/settings/SettingsPage.svelte";
  import Toasts from "$lib/shell/Toasts.svelte";
  import { monitor } from "$lib/stores/monitor.svelte";
  import { PAGES, nav, type Page } from "$lib/stores/nav.svelte";
  import ConnectionsPage from "$lib/pages/connections/ConnectionsPage.svelte";
  import LivePage from "$lib/pages/live/LivePage.svelte";
  import MapPage from "$lib/pages/map/MapPage.svelte";
  import { session } from "$lib/stores/session.svelte";
  import { settings } from "$lib/stores/settings.svelte";

  onMount(() => {
    session.init();
    let off = () => {};
    session.listenChanges().then((f) => (off = f));
    return () => off();
  });

  // Sessions an agent starts measure with the same Settings a click would.
  $effect(() => {
    void [settings.busyRatio, settings.spikeRatio, settings.baselineRiseSecs, settings.reverseDns];
    untrack(() => session.pushDefaults());
  });

  // Number keys open pages, unless typing in a field.
  function onKey(e: KeyboardEvent) {
    if (e.ctrlKey || e.altKey || e.metaKey || e.repeat) return;
    const t = e.target as HTMLElement | null;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    const p = PAGES.find((x) => x.key === e.key);
    if (p) {
      e.preventDefault();
      nav.go(p.id);
    }
  }

  // Each page keeps its scroll position while the app runs.
  let mainEl = $state<HTMLElement | null>(null);
  let shownPage: Page = nav.page;
  $effect.pre(() => {
    const p = nav.page;
    untrack(() => {
      if (p === shownPage || !mainEl) return;
      nav.scroll.set(shownPage, mainEl.scrollTop);
      shownPage = p;
      if (p === "archive") session.archiveKey++;
      tick().then(() => {
        if (mainEl) mainEl.scrollTop = nav.scroll.get(p) ?? 0;
      });
    });
  });

  // Host mode: who owns the target? (an online lookup may arrive a moment later)
  $effect(() => {
    const ip = monitor.session?.mode === "host" ? monitor.session.target : null;
    session.hostOwner = null;
    if (!ip) return;
    let tries = 0;
    let gone = false; // a lookup still in flight when the target changes must not land
    let t: ReturnType<typeof setTimeout> | undefined;
    const look = () =>
      api.geoLookup(ip).then((o) => {
        if (gone) return;
        if (o) session.hostOwner = o;
        else if (++tries < 5) t = setTimeout(look, 2000);
      });
    t = setTimeout(look, 0);
    return () => {
      gone = true;
      clearTimeout(t);
    };
  });
</script>

<svelte:window onkeydown={onKey} />

<div class="app">
  <Rail live={monitor.phase === "running"} recording={monitor.recording !== null} />
  <div class="column">
    <HeaderStatus />

    <main bind:this={mainEl}>
      {#if !inTauri}
        <div class="banner demo" role="status">
          <b>Browser preview.</b>
          <span>Traffic is simulated. Run <code>npm run tauri dev</code> for real capture.</span>
        </div>
      {/if}
      <Toasts />

      {#if nav.page === "live"}
        <LivePage />
      {:else if nav.page === "connections"}
        <ConnectionsPage />
      {:else if nav.page === "map"}
        <MapPage />
      {:else if nav.page === "archive"}
        <ArchivePage bind:openId={session.openRecording} refreshKey={session.archiveKey} />
      {:else}
        <SettingsPage running={monitor.phase === "running"} onapply={() => session.restart()} />
      {/if}
    </main>
  </div>
</div>

<style>
  .app {
    display: flex;
    height: 100vh;
  }
  .column {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
  main {
    flex: 1;
    overflow-y: auto;
    padding: 16px 20px 24px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .banner {
    display: flex;
    gap: 10px;
    align-items: center;
    padding: 10px 14px;
    border-radius: var(--radius);
    font-size: 13px;
  }
  .banner.demo {
    background: var(--accent-wash);
    border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent);
    color: var(--text-secondary);
  }
  .banner.demo b {
    color: var(--text-primary);
  }
  .banner code {
    font-family: var(--font-mono);
    color: var(--accent-strong);
  }
</style>
