<script lang="ts">
  /**
   * Settings → Diagnostics: where the log file is, and a button to open the
   * folder. The file is what a bug report should come with.
   */
  import { onMount } from "svelte";
  import { api, errorMessage } from "$lib/api";

  let location = $state("");
  let error = $state<string | null>(null);

  onMount(async () => {
    location = await api.logsLocation().catch(() => "");
  });

  async function open() {
    error = null;
    try {
      await api.openLogsFolder();
    } catch (e) {
      error = errorMessage(e);
    }
  }
</script>

<h2 class="card-title">Log file</h2>
<p class="muted">
  Fishe writes what it does (sessions, captures, agents, errors) to <code>fishe.log</code>, kept at 2 MB with one older copy.
  Attach it to a bug report. For more detail, start Fishe with <code>FISHE_LOG=debug</code> (or per module, e.g. <code>FISHE_LOG=info,fishe_lib::lan=trace</code>).
</p>
<div class="where">
  <span class="mono path" title="Logs folder">{location || "…"}</span>
  <button type="button" onclick={open}>Open logs folder</button>
</div>
{#if error}<span class="err">{error}</span>{/if}

<style>
  p {
    margin: 0;
    font-size: 13px;
    line-height: 1.45;
    max-width: 68ch;
  }
  code {
    font-size: 12px;
    padding: 1px 4px;
    border-radius: 4px;
    background: var(--surface-2);
  }
  .where {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    min-height: 32px;
  }
  .path {
    font-size: 12px;
    color: var(--text-secondary);
    overflow-wrap: anywhere;
  }
  button {
    padding: 6px 12px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    background: var(--surface-2);
    color: var(--text-primary);
    cursor: pointer;
  }
  button:hover {
    background: var(--surface-1);
  }
</style>
