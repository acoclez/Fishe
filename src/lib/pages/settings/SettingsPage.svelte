<script lang="ts">
  /**
   * Settings as a page: a section index on the left, sections on the right.
   * `nav.section` (from the Agents chip, or any deep link) scrolls to one.
   */
  import { tick } from "svelte";
  import { PRESETS, WINDOWS, settings } from "$lib/stores/settings.svelte";
  import { SETTINGS_SECTIONS, nav, type SettingsSection } from "$lib/stores/nav.svelte";
  import GeoSettings from "./GeoSettings.svelte";
  import AgentsSettings from "./AgentsSettings.svelte";
  import DiagnosticsSettings from "./DiagnosticsSettings.svelte";

  let { running, onapply }: { running: boolean; onapply: () => void } = $props();

  let dirty = $state(false);
  let current = $state<SettingsSection>("measure");
  const els: Partial<Record<SettingsSection, HTMLElement>> = {};

  function pick(id: (typeof PRESETS)[number]["id"]) {
    if (id !== settings.preset) {
      settings.applyPreset(id);
      dirty = running;
    }
  }

  function jump(id: SettingsSection, smooth = true) {
    current = id;
    els[id]?.scrollIntoView({ behavior: smooth ? "smooth" : "instant", block: "start" });
  }

  $effect(() => {
    const id = nav.section;
    if (!id) return;
    tick().then(() => {
      jump(id, false);
      nav.section = null;
    });
  });

  // The index follows the section in view.
  $effect(() => {
    const io = new IntersectionObserver(
      (entries) => {
        const top = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (top) current = (top.target as HTMLElement).dataset.section as SettingsSection;
      },
      { rootMargin: "0px 0px -60% 0px" },
    );
    for (const el of Object.values(els)) if (el) io.observe(el);
    return () => io.disconnect();
  });
</script>

<div class="settings">
  <nav class="index" aria-label="Settings sections">
    {#each SETTINGS_SECTIONS as sec (sec.id)}
      <button type="button" class:on={current === sec.id} onclick={() => jump(sec.id)}>
        <b>{sec.label}</b>
        <small>{sec.hint}</small>
      </button>
    {/each}
  </nav>

  <div class="sections">
    <section class="card" bind:this={els.measure} data-section="measure">
      <h2 class="card-title">Sensitivity</h2>
      <div class="presets" role="radiogroup" aria-label="Sensitivity">
        {#each PRESETS as p (p.id)}
          <button type="button" role="radio" aria-checked={settings.preset === p.id} class:on={settings.preset === p.id} onclick={() => pick(p.id)}>
            <b>{p.label}</b>
            <small>{p.hint}</small>
          </button>
        {/each}
      </div>
      <div class="apply" class:hidden={!dirty}>
        <span>Applies to the next session.</span>
        <button type="button" class="link" onclick={() => { dirty = false; onapply(); }}>Restart now</button>
      </div>
      <div class="row">
        <div>
          <h2 class="card-title">Units</h2>
          <div class="seg" role="radiogroup" aria-label="Units">
            <button type="button" role="radio" aria-checked={settings.units === "bits"} class:on={settings.units === "bits"} onclick={() => (settings.units = "bits")}>bits/s</button>
            <button type="button" role="radio" aria-checked={settings.units === "bytes"} class:on={settings.units === "bytes"} onclick={() => (settings.units = "bytes")}>bytes/s</button>
          </div>
        </div>
        <div>
          <h2 class="card-title">Chart window</h2>
          <div class="seg" role="radiogroup" aria-label="Chart window">
            {#each WINDOWS as w (w)}
              <button type="button" role="radio" aria-checked={settings.windowSecs === w} class:on={settings.windowSecs === w} onclick={() => (settings.windowSecs = w)}>
                {w < 60 ? `${w}s` : `${w / 60}m`}
              </button>
            {/each}
          </div>
        </div>
      </div>
    </section>

    <section class="card" bind:this={els.capture} data-section="capture">
      <div class="row">
        <div>
          <h2 class="card-title">Recording</h2>
          <label class="check" title="Also write the headers of every counted packet to a .pcapng file you can open in Wireshark">
            <input type="checkbox" checked={settings.recordPcap} onchange={(e) => (settings.recordPcap = (e.currentTarget as HTMLInputElement).checked)} />
            Save packet headers (.pcapng)
          </label>
        </div>
        <div>
          <h2 class="card-title">Endpoint names</h2>
          <label class="check" title="Look up PTR records for endpoints without a DNS or TLS name. Sends those addresses to your DNS server.">
            <input type="checkbox" checked={settings.reverseDns} onchange={(e) => (settings.reverseDns = (e.currentTarget as HTMLInputElement).checked)} />
            Reverse DNS lookups
          </label>
        </div>
      </div>
    </section>

    <section class="card" bind:this={els.owners} data-section="owners">
      <GeoSettings />
    </section>

    <section class="card" bind:this={els.agents} data-section="agents">
      <AgentsSettings />
    </section>

    <section class="card" bind:this={els.diagnostics} data-section="diagnostics">
      <DiagnosticsSettings />
    </section>
  </div>
</div>

<style>
  .settings {
    display: grid;
    grid-template-columns: 220px minmax(0, 1fr);
    gap: 18px;
    align-items: start;
  }
  .index {
    position: sticky;
    top: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .index button {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 9px 12px;
    border: 1px solid transparent;
    border-radius: var(--radius);
    background: none;
    color: var(--text-secondary);
    text-align: left;
    cursor: pointer;
  }
  .index button small {
    color: var(--text-muted);
    font-size: 11.5px;
  }
  .index button:hover {
    background: var(--surface-1);
  }
  .index button.on {
    background: var(--surface-1);
    border-color: var(--border);
    color: var(--text-primary);
  }
  .sections {
    display: flex;
    flex-direction: column;
    gap: 14px;
    min-width: 0;
    /* Lets the last section scroll to the top of the page. */
    padding-bottom: 40vh;
  }
  .sections > section {
    padding: 16px 18px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    scroll-margin-top: 4px;
  }
  .row {
    display: flex;
    gap: 28px;
    flex-wrap: wrap;
    margin-top: 6px;
  }
  .row > div {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .presets {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
  }
  .presets button {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 3px;
    padding: 10px 12px;
    text-align: left;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    cursor: pointer;
  }
  .presets button small {
    color: var(--text-muted);
    font-size: 11.5px;
  }
  .presets button.on {
    border-color: var(--accent);
    background: var(--accent-wash);
  }
  .seg {
    padding: 3px;
    border-radius: var(--radius);
  }
  .seg button {
    padding: 6px 12px;
    border-radius: 7px;
  }
  .check {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 32px;
    font-size: 13px;
    color: var(--text-secondary);
    cursor: pointer;
  }
  .check input {
    accent-color: var(--accent);
    width: 15px;
    height: 15px;
  }
  .apply {
    display: flex;
    gap: 10px;
    align-items: center;
    height: 18px;
    font-size: 12px;
    color: var(--text-muted);
  }
  .apply.hidden {
    visibility: hidden;
  }
  .link {
    border: 0;
    background: none;
    color: var(--accent-strong);
    cursor: pointer;
    padding: 0;
    font-weight: 600;
  }
  @media (max-width: 900px) {
    .settings {
      grid-template-columns: 1fr;
    }
    .index {
      position: static;
      flex-direction: row;
      flex-wrap: wrap;
    }
  }
</style>
