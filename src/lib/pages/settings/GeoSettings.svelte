<script lang="ts">
  /** Settings: offline owner database (DB-IP Lite) and opt-in online lookup. */
  import { onMount } from "svelte";
  import { api, errorMessage } from "#lib/api/index.ts";
  import { formatBytes } from "#lib/utils/format.ts";
  import { settings } from "#lib/stores/settings.svelte.ts";
  import type { GeoProgress, GeoStatus } from "#lib/api/types.ts";
  import ConfirmDialog from "../../components/ConfirmDialog.svelte";

  let status = $state<GeoStatus | null>(null);
  let busy = $state<"download" | "remove" | null>(null);
  let progress = $state<GeoProgress | null>(null);
  let error = $state<string | null>(null);
  let confirmRemove = $state(false);

  onMount(async () => {
    try {
      status = await api.geoStatus();
    } catch (err) {
      error = errorMessage(err);
    }
  });

  async function download() {
    busy = "download";
    error = null;
    progress = null;
    try {
      status = await api.geoDownload((p) => (progress = p));
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = null;
      progress = null;
    }
  }

  async function remove() {
    busy = "remove";
    try {
      status = await api.geoRemove();
      confirmRemove = false;
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = null;
    }
  }

  async function toggleOnline(on: boolean) {
    settings.onlineLookup = on;
    try {
      status = await api.setOnlineLookup(on);
    } catch (err) {
      error = errorMessage(err);
    }
  }

  const pct = $derived(progress?.total ? Math.min(100, (progress.received / progress.total) * 100) : null);
  const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
</script>

<div class="geo">
  <h2 class="card-title">Owner & country</h2>

  <div class="row">
    <div class="state">
      {#if !status}
        <span class="muted">Checking…</span>
      {:else if status.installed}
        <b>DB-IP Lite {status.month ?? ""}</b>
        <span class="muted">
          · {formatBytes(status.bytes)}{#if status.builtAt} · built {dateFmt.format(new Date(status.builtAt))}{/if}
        </span>
        {#if status.updateAvailable}<span class="tag">{status.currentMonth} available</span>{/if}
      {:else}
        <span>Not installed.</span>
        <span class="muted">Shows who owns each Internet address (e.g. Cloudflare, AS13335) and its country.</span>
      {/if}
    </div>
    <div class="buttons">
      {#if busy === "download"}
        <span class="progress" aria-live="polite">
          {progress ? `${progress.file === "asn" ? "Owners" : "Countries"} ${formatBytes(progress.received)}${pct !== null ? ` · ${Math.round(pct)}%` : ""}` : "Connecting…"}
        </span>
      {:else}
        <button type="button" class="primary" onclick={download} disabled={busy !== null}>
          {status?.installed ? (status.updateAvailable ? "Update" : "Re-download") : "Download (~10 MB)"}
        </button>
        {#if status?.installed}
          <button type="button" onclick={() => (confirmRemove = true)} disabled={busy !== null}>Remove</button>
        {/if}
      {/if}
    </div>
  </div>
  {#if busy === "download"}
    <div class="bar" role="progressbar" aria-valuenow={pct ?? undefined} aria-valuemin="0" aria-valuemax="100">
      <span style:width="{pct ?? 15}%" class:indeterminate={pct === null}></span>
    </div>
  {/if}

  <p class="note">
    Downloaded from <span class="mono">download.db-ip.com</span> only when you click. Lookups then run on this machine.
    {#if status}<br /><span class="attribution">{status.attribution} (db-ip.com).</span>{/if}
  </p>

  <label class="check">
    <input type="checkbox" checked={settings.onlineLookup} onchange={(e) => toggleOnline((e.currentTarget as HTMLInputElement).checked)} />
    <span>
      Look up unknown addresses online
      <small>Sends Internet addresses the offline data doesn't cover to <span class="mono">ipinfo.io</span> (about 1 per second).</small>
    </span>
  </label>

  {#if error}<p class="error" role="alert">{error}</p>{/if}
</div>

{#if confirmRemove}
  <ConfirmDialog title="Remove the owner database?" confirmLabel="Remove" danger busy={busy === "remove"} onconfirm={remove} oncancel={() => (confirmRemove = false)}>
    <p>The DB-IP Lite files ({formatBytes(status?.bytes ?? 0)}) will be deleted. Endpoints will show no owner or country until you download them again.</p>
  </ConfirmDialog>
{/if}

<style>
  .geo {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }
  .state {
    font-size: 13px;
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
  }
  .tag {
    padding: 0 6px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    border: 1px solid var(--accent);
    color: var(--accent-strong);
  }
  .buttons {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  button {
    height: 30px;
    padding: 0 12px;
    border-radius: 8px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
  }
  button.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: #04121a;
  }
  button:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .progress {
    font-size: 12px;
    color: var(--text-secondary);
  }
  .bar {
    height: 6px;
    border-radius: 3px;
    background: var(--surface-3);
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 200ms;
  }
  .bar span.indeterminate {
    animation: slide 1.2s ease-in-out infinite;
  }
  @keyframes slide {
    0% {
      transform: translateX(-100%);
    }
    100% {
      transform: translateX(700%);
    }
  }
  .note {
    margin: 0;
    font-size: 12px;
    color: var(--text-muted);
  }
  .attribution {
    color: var(--text-secondary);
  }
  .check {
    display: flex;
    gap: 8px;
    align-items: flex-start;
    font-size: 13px;
    color: var(--text-secondary);
    cursor: pointer;
  }
  .check input {
    accent-color: var(--accent);
    width: 15px;
    height: 15px;
    margin-top: 2px;
  }
  .check small {
    display: block;
    color: var(--text-muted);
    font-size: 11.5px;
  }
  .error {
    margin: 0;
    padding: 6px 10px;
    border-radius: 6px;
    background: var(--danger-wash);
    font-size: 12px;
  }
</style>
