<script lang="ts">
  /**
   * Searchable process picker.
   *
   * Lists processes grouped by executable (busiest network users first,
   * refreshed while open). Picking a group binds by name: all instances,
   * including future ones. Expanding a group lets you bind to one PID.
   */
  import { api, errorMessage } from "#lib/api/index.ts";
  import { settings } from "#lib/stores/settings.svelte.ts";
  import type { ProcessGroup, ProcessSelector } from "#lib/api/types.ts";

  interface Props {
    selection: ProcessSelector | null;
    disabled?: boolean;
  }
  let { selection = $bindable(), disabled = false }: Props = $props();

  let open = $state(false);
  let query = $state("");
  let groups = $state<ProcessGroup[]>([]);
  let loading = $state(false);
  let loadError = $state<string | null>(null);
  let expanded = $state<string | null>(null);
  let active = $state(0);
  let root: HTMLDivElement;
  let input: HTMLInputElement;

  const filtered = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? groups.filter((g) => g.name.toLowerCase().includes(q) || g.pids.some((p) => String(p).startsWith(q)))
      : groups;
    return list.slice(0, 200);
  });

  const display = $derived.by(() => {
    if (!selection) return "";
    if (selection.by === "name") return selection.name;
    const pid = selection.pid;
    const g = groups.find((x) => x.pids.includes(pid));
    return g ? `${g.name} · PID ${pid}` : `PID ${pid}`;
  });

  async function refresh() {
    loading = groups.length === 0;
    try {
      groups = await api.listProcesses();
      loadError = null;
    } catch (err) {
      loadError = errorMessage(err);
    } finally {
      loading = false;
    }
  }

  // Refresh every 3 s while the list is open.
  $effect(() => {
    if (!open) return;
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  });

  function openList() {
    if (disabled) return;
    open = true;
    query = "";
    active = 0;
  }

  function choose(sel: ProcessSelector) {
    selection = sel;
    open = false;
    expanded = null;
    input?.blur();
  }

  function onKey(e: KeyboardEvent) {
    if (!open && (e.key === "ArrowDown" || e.key === "Enter")) {
      openList();
      e.preventDefault();
      return;
    }
    if (!open) return;
    if (e.key === "ArrowDown") {
      active = Math.min(active + 1, filtered.length - 1);
      e.preventDefault();
    } else if (e.key === "ArrowUp") {
      active = Math.max(active - 1, 0);
      e.preventDefault();
    } else if (e.key === "Enter") {
      const g = filtered[active];
      if (g) choose({ by: "name", name: g.name });
      else if (query.trim()) choose({ by: "name", name: query.trim() });
      e.preventDefault();
    } else if (e.key === "Escape") {
      open = false;
    } else if (e.key === "ArrowRight" && filtered[active]) {
      expanded = filtered[active].name;
    }
  }

  function onFocusOut(e: FocusEvent) {
    if (!root.contains(e.relatedTarget as Node | null)) open = false;
  }
</script>

<div class="picker" bind:this={root} onfocusout={onFocusOut}>
  <input
    bind:this={input}
    class="mono"
    value={open ? query : display}
    oninput={(e) => {
      query = (e.currentTarget as HTMLInputElement).value;
      active = 0;
    }}
    onfocus={openList}
    onclick={openList}
    onkeydown={onKey}
    placeholder="Search a running program, e.g. chrome.exe"
    role="combobox"
    aria-expanded={open}
    aria-controls="process-list"
    aria-autocomplete="list"
    spellcheck="false"
    autocomplete="off"
    {disabled}
  />

  {#if open}
    <div class="list" id="process-list" role="listbox" tabindex="-1">
      {#if !query && settings.recentProcesses.length}
        <div class="recent">
          <span>Recent</span>
          {#each settings.recentProcesses as r (r)}
            <button type="button" class="chip mono" onclick={() => choose({ by: "name", name: r })}>{r}</button>
          {/each}
        </div>
      {/if}
      {#if loading}
        <div class="empty">Loading processes…</div>
      {:else if loadError}
        <div class="empty error">{loadError}</div>
      {:else if filtered.length === 0}
        <div class="empty">
          No running process matches.
          {#if query.trim()}
            <button type="button" class="link" onclick={() => choose({ by: "name", name: query.trim() })}>
              Wait for “{query.trim()}” to start
            </button>
          {/if}
        </div>
      {:else}
        {#each filtered as g, i (g.name)}
          <div class="row" class:active={i === active} role="option" aria-selected={i === active}>
            <button type="button" class="main" onclick={() => choose({ by: "name", name: g.name })} onmouseenter={() => (active = i)}>
              <span class="name mono">{g.name}</span>
              <span class="meta">
                {g.pids.length} {g.pids.length === 1 ? "process" : "processes"}
                {#if g.connections}<span class="conn">· {g.connections} connections</span>{/if}
                {#if g.listening}<span>· {g.listening} listening</span>{/if}
              </span>
            </button>
            {#if g.pids.length > 1}
              <button
                type="button"
                class="expand"
                aria-label="Show individual PIDs of {g.name}"
                aria-expanded={expanded === g.name}
                onclick={() => (expanded = expanded === g.name ? null : g.name)}
              >
                <svg viewBox="0 0 16 16" class:open={expanded === g.name}><path d="M6 4l4 4-4 4" /></svg>
              </button>
            {:else}
              <button type="button" class="pid mono" title="Bind to this PID only" onclick={() => choose({ by: "pid", pid: g.pids[0] })}>
                {g.pids[0]}
              </button>
            {/if}
          </div>
          {#if expanded === g.name}
            <div class="pids">
              {#each g.pids as pid (pid)}
                <button type="button" class="pid mono" title="Bind to this PID only" onclick={() => choose({ by: "pid", pid })}>
                  PID {pid}
                </button>
              {/each}
            </div>
          {/if}
        {/each}
      {/if}
      <div class="hint">Pick a program to follow all its instances, or a PID to follow just one.</div>
    </div>
  {/if}
</div>

<style>
  .picker {
    position: relative;
    min-width: 0;
  }
  input {
    width: 100%;
    height: 38px;
    padding: 0 12px;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    outline: none;
    transition: border-color 150ms, box-shadow 150ms;
  }
  input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-wash);
  }
  input:disabled {
    color: var(--text-secondary);
    opacity: 0.8;
  }
  input::placeholder {
    color: var(--text-muted);
    font-family: var(--font-ui), sans-serif;
  }
  .list {
    position: absolute;
    z-index: 20;
    top: calc(100% + 6px);
    left: 0;
    right: 0;
    max-height: 360px;
    overflow-y: auto;
    padding: 6px;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.5);
  }
  .recent {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    padding: 4px 6px 8px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 4px;
    font-size: 11px;
    color: var(--text-muted);
  }
  .chip {
    padding: 2px 8px;
    border-radius: 999px;
    border: 1px solid var(--border-strong);
    background: var(--surface-3);
    font-size: 12px;
    cursor: pointer;
  }
  .chip:hover {
    border-color: var(--accent);
  }
  .row {
    display: flex;
    align-items: center;
    gap: 4px;
    border-radius: 7px;
  }
  .row.active {
    background: var(--accent-wash);
  }
  .main {
    flex: 1;
    display: flex;
    align-items: baseline;
    gap: 10px;
    min-width: 0;
    padding: 7px 8px;
    border: 0;
    background: none;
    text-align: left;
    cursor: pointer;
  }
  .name {
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .meta {
    font-size: 12px;
    color: var(--text-muted);
    white-space: nowrap;
  }
  .conn {
    color: var(--accent-strong);
  }
  .expand {
    width: 28px;
    height: 28px;
    border: 0;
    border-radius: 6px;
    background: none;
    color: var(--text-secondary);
    cursor: pointer;
  }
  .expand:hover {
    background: var(--surface-3);
  }
  .expand svg {
    width: 14px;
    height: 14px;
    fill: none;
    stroke: currentColor;
    stroke-width: 2;
    transition: transform 150ms;
  }
  .expand svg.open {
    transform: rotate(90deg);
  }
  .pids {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    padding: 4px 8px 8px 20px;
  }
  .pid {
    padding: 2px 8px;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    background: var(--surface-3);
    color: var(--text-secondary);
    font-size: 12px;
    cursor: pointer;
  }
  .pid:hover {
    color: var(--text-primary);
    border-color: var(--accent);
  }
  .empty {
    padding: 12px 8px;
    color: var(--text-muted);
    display: flex;
    flex-direction: column;
    gap: 6px;
    align-items: flex-start;
  }
  .empty.error {
    color: var(--danger);
  }
  .link {
    border: 0;
    background: none;
    padding: 0;
    color: var(--accent-strong);
    cursor: pointer;
    font-weight: 600;
  }
  .hint {
    padding: 8px 8px 2px;
    margin-top: 4px;
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--text-muted);
  }
</style>
