<script lang="ts">
  /** Saved recordings: list, rename, export, reveal, delete; opens a replay. */
  import { onMount } from "svelte";
  import { api, errorMessage } from "$lib/api";
  import { formatBytes, formatDuration, rateText } from "$lib/utils/format";
  import { settings } from "$lib/stores/settings.svelte";
  import type { ExportFormat, RecordingSummary } from "$lib/api/types";
  import LevelBadge from "../../components/LevelBadge.svelte";
  import ConfirmDialog from "../../components/ConfirmDialog.svelte";
  import RecordingView from "./RecordingView.svelte";

  let { openId = $bindable(null), refreshKey = 0 }: { openId?: number | null; refreshKey?: number } = $props();

  let items = $state<RecordingSummary[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);
  let location = $state("");
  let editing = $state<number | null>(null);
  let draft = $state("");
  let menuFor = $state<number | null>(null);
  let toDelete = $state<RecordingSummary | null>(null);
  let deleting = $state(false);

  async function load() {
    try {
      items = await api.listRecordings();
      error = null;
    } catch (err) {
      error = errorMessage(err);
    } finally {
      loading = false;
    }
  }

  onMount(async () => {
    location = await api.archiveLocation().catch(() => "");
  });
  $effect(() => {
    void refreshKey;
    void openId;
    load();
  });
  // Keep durations of an in-progress recording fresh.
  $effect(() => {
    if (!items.some((i) => i.status === "recording")) return;
    const t = setInterval(load, 2000);
    return () => clearInterval(t);
  });

  const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

  function startRename(r: RecordingSummary) {
    editing = r.id;
    draft = r.name;
  }
  async function commitRename(r: RecordingSummary) {
    const name = draft.trim();
    editing = null;
    if (!name || name === r.name) return;
    try {
      await api.renameRecording(r.id, name);
      await load();
    } catch (err) {
      error = errorMessage(err);
    }
  }

  async function doExport(r: RecordingSummary, format: ExportFormat) {
    menuFor = null;
    const base = r.name.replace(/[\\/:*?"<>|]+/g, "_").slice(0, 80) || `recording-${r.id}`;
    const suffix = format === "samplesCsv" ? "-samples" : format === "endpointsCsv" ? "-endpoints" : "";
    try {
      const path = await api.exportRecording(r.id, format, base + suffix);
      if (path) notice = `Exported to ${path}`;
    } catch (err) {
      error = errorMessage(err);
    }
  }

  async function reveal(path: string) {
    try {
      await api.revealInFolder(path);
    } catch (err) {
      error = errorMessage(err);
    }
  }

  async function confirmDelete() {
    if (!toDelete) return;
    deleting = true;
    try {
      await api.deleteRecording(toDelete.id);
      notice = `Deleted “${toDelete.name}”.`;
      toDelete = null;
      await load();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      deleting = false;
    }
  }
</script>

{#if openId !== null}
  <RecordingView id={openId} units={settings.units} onback={() => (openId = null)} />
{:else}
  <section class="card panel">
    <header>
      <h2 class="card-title">Recordings <span class="count num">{items.length}</span></h2>
      {#if location}<span class="where mono" title="Archive folder">{location}</span>{/if}
    </header>

    {#if error}<p class="msg error" role="alert">{error} <button type="button" onclick={() => (error = null)}>×</button></p>{/if}
    {#if notice}<p class="msg" role="status">{notice} <button type="button" onclick={() => (notice = null)}>×</button></p>{/if}

    {#if loading}
      <p class="empty">Loading…</p>
    {:else if items.length === 0}
      <div class="empty">
        <p><b>No recordings yet.</b></p>
        <p>Start monitoring, then press <span class="kbd">● Record</span> to save the session here.</p>
      </div>
    {:else}
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Target</th>
            <th>Started</th>
            <th class="r">Duration</th>
            <th class="r">Data</th>
            <th class="r">Peak</th>
            <th>Max</th>
            <th>Packets file</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each items as r (r.id)}
            <tr>
              <td class="name">
                {#if editing === r.id}
                  <input
                    bind:value={draft}
                    onblur={() => commitRename(r)}
                    onkeydown={(e) => {
                      if (e.key === "Enter") (e.currentTarget as HTMLInputElement).blur();
                      if (e.key === "Escape") editing = null;
                    }}
                    aria-label="Recording name"
                  />
                {:else}
                  <button type="button" class="link" onclick={() => (openId = r.id)} title="Open">{r.name}</button>
                  <button type="button" class="ghost" onclick={() => startRename(r)} aria-label="Rename {r.name}" title="Rename">✎</button>
                {/if}
                {#if r.status !== "complete"}<span class="tag" class:live={r.status === "recording"}>{r.status}</span>{/if}
              </td>
              <td>{#if r.mode === "all"}<span class="mode">All traffic</span>{:else}<span class="mode">{r.mode === "process" ? "Process" : "Host"}</span> <span class="mono">{r.label}</span>{/if}</td>
              <td class="muted">{dateFmt.format(new Date(r.startedAt))}</td>
              <td class="r num">{formatDuration(r.durationMs)}</td>
              <td class="r num">↓ {formatBytes(r.totals.bytesIn)}<br /><span class="muted">↑ {formatBytes(r.totals.bytesOut)}</span></td>
              <td class="r num">{rateText(r.peakBps, settings.units)}</td>
              <td><LevelBadge level={r.maxLevel} size="sm" /></td>
              <td>
                {#if r.pcapPath}
                  <button type="button" class="ghost file" onclick={() => reveal(r.pcapPath!)} title="Show in Explorer: {r.pcapPath}">
                    .pcapng · {r.pcapPackets.toLocaleString()} pkts{#if r.pcapBytes !== null} · {formatBytes(r.pcapBytes)}{/if}
                  </button>
                  {#if r.pcapDropped > 0}<span class="warn" title="Packets the file writer couldn't keep up with (not missing from the measurements)">{r.pcapDropped} skipped</span>{/if}
                {:else}
                  <span class="muted">–</span>
                {/if}
              </td>
              <td class="actions">
                <button type="button" onclick={() => (openId = r.id)} disabled={r.status === "recording"}>Open</button>
                <div class="menu">
                  <button type="button" onclick={() => (menuFor = menuFor === r.id ? null : r.id)} aria-expanded={menuFor === r.id} disabled={r.status === "recording"}>Export ▾</button>
                  {#if menuFor === r.id}
                    <div class="pop" role="menu">
                      <button type="button" role="menuitem" onclick={() => doExport(r, "samplesCsv")}>Samples (.csv)</button>
                      <button type="button" role="menuitem" onclick={() => doExport(r, "endpointsCsv")} disabled={r.endpointCount === 0}>Endpoints (.csv)</button>
                      <button type="button" role="menuitem" onclick={() => doExport(r, "json")}>Everything (.json)</button>
                    </div>
                  {/if}
                </div>
                <button type="button" class="del" onclick={() => (toDelete = r)} disabled={r.status === "recording"} aria-label="Delete {r.name}">Delete</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
{/if}

{#if toDelete}
  <ConfirmDialog title="Delete recording?" confirmLabel="Delete permanently" danger busy={deleting} onconfirm={confirmDelete} oncancel={() => (toDelete = null)}>
    <p>
      “<b>{toDelete.name}</b>” ({formatDuration(toDelete.durationMs)}, {formatBytes(toDelete.totals.bytesIn + toDelete.totals.bytesOut)})
      will be removed from the archive{#if toDelete.pcapPath}, together with its packets file{/if}.
    </p>
    <p>This can't be undone.</p>
  </ConfirmDialog>
{/if}

<style>
  .panel {
    padding: 16px 18px;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
  }
  .count {
    margin-left: 6px;
    color: var(--text-muted);
  }
  .where {
    font-size: 11px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 60%;
  }
  .msg {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 10px 0 0;
    padding: 8px 12px;
    border-radius: 8px;
    background: var(--accent-wash);
    font-size: 13px;
    color: var(--text-secondary);
    word-break: break-all;
  }
  .msg.error {
    background: var(--danger-wash);
  }
  .msg button {
    margin-left: auto;
    border: 0;
    background: none;
    cursor: pointer;
    font-size: 16px;
    color: var(--text-secondary);
  }
  .empty {
    color: var(--text-muted);
    padding: 24px 4px 12px;
  }
  .empty p {
    margin: 4px 0;
  }
  .kbd {
    padding: 1px 6px;
    border: 1px solid var(--border-strong);
    border-radius: 5px;
    color: var(--text-secondary);
  }
  table {
    width: 100%;
    margin-top: 12px;
    border-collapse: collapse;
    font-size: 13px;
  }
  th {
    text-align: left;
    font-weight: 500;
    font-size: 11px;
    color: var(--text-muted);
    padding: 4px 8px 6px;
  }
  td {
    padding: 8px;
    border-top: 1px solid var(--border);
    vertical-align: middle;
  }
  .r {
    text-align: right;
  }
  .name {
    min-width: 200px;
  }
  .name input {
    width: 100%;
    height: 28px;
    padding: 0 8px;
    background: var(--surface-2);
    border: 1px solid var(--accent);
    border-radius: 6px;
    outline: none;
  }
  button {
    cursor: pointer;
  }
  .link {
    border: 0;
    background: none;
    padding: 0;
    font-weight: 600;
    color: var(--text-primary);
    text-align: left;
  }
  .link:hover {
    color: var(--accent-strong);
  }
  .ghost {
    border: 0;
    background: none;
    color: var(--text-muted);
    padding: 0 4px;
  }
  .ghost:hover {
    color: var(--accent-strong);
  }
  .file {
    font-size: 12px;
    text-align: left;
  }
  .warn {
    display: block;
    font-size: 11px;
    color: var(--level-busy);
  }
  .tag {
    margin-left: 6px;
    padding: 0 6px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    border: 1px solid var(--level-busy);
    color: var(--level-busy);
  }
  .tag.live {
    border-color: var(--danger);
    color: var(--danger);
  }
  .mode {
    font-size: 11px;
    color: var(--text-muted);
  }
  .actions {
    white-space: nowrap;
    text-align: right;
  }
  .actions > button,
  .menu > button {
    height: 28px;
    padding: 0 10px;
    margin-left: 4px;
    border-radius: 6px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    font-size: 12px;
  }
  .actions button:disabled {
    opacity: 0.4;
    cursor: default;
  }
  .actions > button:not(:disabled):hover,
  .menu > button:not(:disabled):hover {
    border-color: var(--accent);
  }
  .del:not(:disabled):hover {
    border-color: var(--danger) !important;
    color: var(--danger);
  }
  .menu {
    position: relative;
    display: inline-block;
  }
  .pop {
    position: absolute;
    right: 0;
    top: calc(100% + 4px);
    z-index: 10;
    display: flex;
    flex-direction: column;
    min-width: 170px;
    padding: 4px;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: 8px;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
  }
  .pop button {
    border: 0;
    background: none;
    text-align: left;
    padding: 7px 10px;
    border-radius: 6px;
    font-size: 12px;
  }
  .pop button:hover:not(:disabled) {
    background: var(--accent-wash);
  }
  .pop button:disabled {
    opacity: 0.4;
  }
</style>
