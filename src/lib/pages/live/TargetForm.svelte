<script lang="ts">
  /** Mode switch (Host | Process | All), target input, interface picker, Start/Stop. */
  import type { InterfaceInfo, Mode, ProcessSelector, RecordingTick, TargetSpec } from "#lib/api/types.ts";
  import { formatDuration } from "#lib/utils/format.ts";
  import type { Phase } from "#lib/stores/monitor.svelte.ts";
  import { settings } from "#lib/stores/settings.svelte.ts";
  import ProcessPicker from "./ProcessPicker.svelte";

  interface Props {
    interfaces: InterfaceInfo[];
    phase: Phase;
    disabled: boolean;
    processModeAvailable: boolean;
    onstart: (target: TargetSpec, iface: string | null) => void;
    onstop: () => void;
    onsettings: () => void;
    settingsOpen: boolean;
    /** A recording is active. */
    recording: boolean;
    /** Live recording counters (from the latest sample). */
    recordingTick: RecordingTick | null;
    recordingBusy: boolean;
    onrecord: () => void;
    /** The program picked in process mode (bindable, so the page can set it). */
    selection?: ProcessSelector | null;
  }
  let {
    interfaces, phase, disabled, processModeAvailable, onstart, onstop, onsettings, settingsOpen,
    recording, recordingTick, recordingBusy, onrecord,
    selection = $bindable(null),
  }: Props = $props();

  let host = $state(settings.recentTargets[0] ?? "");
  let iface = $state<string>("");

  const mode = $derived<Mode>(processModeAvailable ? settings.mode : "host");
  const busy = $derived(phase === "starting" || phase === "stopping");
  const running = $derived(phase === "running" || phase === "starting");
  const ready = $derived(mode === "host" ? host.trim().length > 0 : mode === "all" ? true : selection !== null);

  /** Usable adapters first, then the rest. */
  const sorted = $derived(
    [...interfaces].sort((a, b) => score(b) - score(a) || a.description.localeCompare(b.description)),
  );
  function score(i: InterfaceInfo) {
    return (i.isUp ? 2 : 0) + (i.isRunning ? 2 : 0) + (i.addresses.length ? 1 : 0) - (i.isLoopback ? 1 : 0);
  }
  function label(i: InterfaceInfo) {
    const v4 = i.addresses.find((a) => a.includes("."));
    const addr = v4 ?? i.addresses[0];
    return addr ? `${i.description} (${addr})` : i.description;
  }

  function setMode(m: Mode) {
    if (!running) settings.mode = m;
  }

  function submit(e: SubmitEvent) {
    e.preventDefault();
    if (running) {
      onstop();
    } else if (mode === "host" && host.trim()) {
      onstart({ kind: "host", address: host.trim() }, iface || null);
    } else if (mode === "process" && selection) {
      onstart({ kind: "process", selector: selection }, iface || null);
    } else if (mode === "all") {
      onstart({ kind: "all" }, iface || null);
    }
  }
</script>

<form class="bar card" onsubmit={submit}>
  {#if processModeAvailable}
    <div class="field mode">
      <span>Target</span>
      <div class="seg" role="radiogroup" aria-label="Target type">
        <button type="button" role="radio" aria-checked={mode === "host"} class:on={mode === "host"} disabled={running} onclick={() => setMode("host")}>
          <svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6" /><path d="M2 8h12M8 2c2 2 2 10 0 12M8 2c-2 2-2 10 0 12" /></svg>
          Host
        </button>
        <button type="button" role="radio" aria-checked={mode === "process"} class:on={mode === "process"} disabled={running} onclick={() => setMode("process")}>
          <svg viewBox="0 0 16 16" aria-hidden="true"><rect x="2" y="3" width="12" height="10" rx="1.5" /><path d="M2 6h12M5 9h3" /></svg>
          Process
        </button>
        <button type="button" role="radio" aria-checked={mode === "all"} class:on={mode === "all"} disabled={running} onclick={() => setMode("all")} title="Every packet of this machine, labelled with its program">
          <svg viewBox="0 0 16 16" aria-hidden="true"><rect x="5.5" y="1.5" width="5" height="4" rx="1" /><rect x="1.5" y="10.5" width="5" height="4" rx="1" /><rect x="9.5" y="10.5" width="5" height="4" rx="1" /><path d="M8 5.5v2.5M4 10.5V8h8v2.5" /></svg>
          All
        </button>
      </div>
    </div>
  {/if}

  <div class="field target">
    <span id="target-label">{mode === "host" ? "IP address or host name" : mode === "all" ? "Scope" : "Program or PID"}</span>
    {#if mode === "all"}
      <div class="all-note" aria-labelledby="target-label">
        Every packet of this machine, labelled by program
      </div>
    {:else if mode === "host"}
      <input
        class="mono"
        bind:value={host}
        aria-labelledby="target-label"
        placeholder="e.g. 1.1.1.1 or example.com"
        list="recent-targets"
        spellcheck="false"
        autocomplete="off"
        disabled={running || disabled}
      />
      <datalist id="recent-targets">
        {#each settings.recentTargets as t (t)}<option value={t}></option>{/each}
      </datalist>
    {:else}
      <ProcessPicker bind:selection disabled={running || disabled} />
    {/if}
  </div>

  <label class="field iface">
    <span>Interface</span>
    <select bind:value={iface} disabled={running || disabled}>
      <option value="">{mode === "host" ? "Automatic (route to target)" : mode === "all" ? "All network adapters" : "All active interfaces"}</option>
      {#each sorted as i (i.name)}
        <option value={i.name}>{label(i)}</option>
      {/each}
    </select>
  </label>

  <button type="submit" class="primary" class:stop={running} disabled={busy || disabled || (!running && !ready)}>
    {#if phase === "starting"}
      Starting…
    {:else if phase === "stopping"}
      Stopping…
    {:else if running}
      <svg viewBox="0 0 16 16" aria-hidden="true"><rect x="4" y="4" width="8" height="8" rx="1.5" /></svg> Stop
    {:else}
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M5 3.5v9l7.5-4.5z" /></svg> Start
    {/if}
  </button>

  <button
    type="button"
    class="rec"
    class:on={recording}
    disabled={recordingBusy || (!recording && phase !== "running")}
    onclick={onrecord}
    title={recording ? "Stop recording (saved to the Archive)" : "Record this session to the Archive"}
    aria-pressed={recording}
  >
    <i class="dot" aria-hidden="true"></i>
    {#if recording}
      <span class="num">{formatDuration(recordingTick?.elapsedMs ?? 0)}</span>
    {:else}
      Record
    {/if}
  </button>

  <button
    type="button"
    class="icon"
    class:on={settingsOpen}
    onclick={onsettings}
    title="Sensitivity & display settings"
    aria-label="Settings"
    aria-expanded={settingsOpen}
  >
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M4 7h10M18 7h2M4 17h4M12 17h8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
      <circle cx="16" cy="7" r="2.2" fill="none" stroke="currentColor" stroke-width="2" />
      <circle cx="10" cy="17" r="2.2" fill="none" stroke="currentColor" stroke-width="2" />
    </svg>
  </button>
</form>

<style>
  .bar {
    display: flex;
    align-items: flex-end;
    gap: 12px;
    padding: 12px 14px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 5px;
    min-width: 0;
  }
  .field > span {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .mode {
    flex: none;
  }
  .target {
    flex: 1 1 320px;
  }
  .iface {
    flex: 1 1 260px;
  }
  .all-note {
    display: flex;
    align-items: center;
    height: 38px;
    padding: 0 12px;
    background: var(--surface-2);
    border: 1px dashed var(--border-strong);
    border-radius: var(--radius);
    color: var(--text-secondary);
    font-size: 13px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  input,
  select {
    height: 38px;
    padding: 0 12px;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    outline: none;
    min-width: 0;
    transition: border-color 150ms, box-shadow 150ms;
  }
  input:focus,
  select:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-wash);
  }
  input:disabled,
  select:disabled {
    color: var(--text-secondary);
    opacity: 0.8;
  }
  input::placeholder {
    color: var(--text-muted);
    font-family: var(--font-ui), sans-serif;
  }
  select option {
    background: var(--surface-2);
  }
  .seg {
    height: 38px;
    padding: 3px;
    border-radius: var(--radius);
  }
  /* Repeats the shared `border: 0`: the generic `button` rule below would
     otherwise win. Background and colour are left to the shared rules in
     app.css: a scoped rule outranks them, and setting either here would
     hide the filled look of the selected segment. */
  .seg button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 0 12px;
    border: 0;
    border-radius: 7px;
  }
  .seg button svg {
    width: 14px;
    height: 14px;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.4;
  }
  .seg button:disabled:not(.on) {
    opacity: 0.45;
    cursor: default;
  }
  button {
    height: 38px;
    border-radius: var(--radius);
    border: 1px solid transparent;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 7px;
    transition: background 150ms, border-color 150ms, opacity 150ms;
  }
  .seg button {
    height: auto;
  }
  button:disabled {
    cursor: default;
  }
  .primary:disabled {
    opacity: 0.45;
  }
  .primary {
    min-width: 112px;
    padding: 0 18px;
    font-weight: 600;
    background: var(--accent);
    color: #04121a;
  }
  .primary:not(:disabled):hover {
    background: var(--accent-strong);
  }
  .primary.stop {
    background: var(--surface-3);
    color: var(--text-primary);
    border-color: var(--border-strong);
  }
  .primary.stop:not(:disabled):hover {
    border-color: var(--danger);
    background: var(--danger-wash);
  }
  .primary svg {
    width: 14px;
    height: 14px;
    fill: currentColor;
  }
  .rec {
    min-width: 96px;
    padding: 0 14px;
    background: var(--surface-2);
    border-color: var(--border-strong);
    color: var(--text-secondary);
    font-weight: 600;
  }
  .rec:disabled {
    opacity: 0.45;
  }
  .rec:not(:disabled):hover {
    border-color: var(--danger);
    color: var(--text-primary);
  }
  .rec .dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--danger);
  }
  .rec.on {
    border-color: var(--danger);
    background: var(--danger-wash);
    color: var(--text-primary);
  }
  .rec.on .dot {
    animation: recblink 1.2s ease-in-out infinite;
    will-change: opacity;
  }
  @keyframes recblink {
    50% {
      opacity: 0.25;
    }
  }
  .icon {
    width: 38px;
    background: var(--surface-2);
    border-color: var(--border-strong);
    color: var(--text-secondary);
  }
  .icon:hover,
  .icon.on {
    color: var(--accent-strong);
    border-color: var(--accent);
  }
  .icon svg {
    width: 20px;
    height: 20px;
  }
  @media (max-width: 860px) {
    .bar {
      flex-wrap: wrap;
    }
  }
</style>
