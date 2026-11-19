<script lang="ts">
  /**
   * The Live page's short list: the five busiest programs or endpoints, with
   * a link to the full table on the Connections page. Fixed height (five
   * rows, empty ones kept), order held like the big tables (StableList).
   */
  import { flip } from "svelte/animate";
  import { StableList } from "$lib/stores/stable.svelte";
  import { formatRate } from "$lib/utils/format";
  import type { TopItem, Units } from "$lib/api/types";

  let {
    title,
    items,
    total,
    nowMs,
    units,
    focused = null,
    onpick,
    onall,
  }: {
    title: string;
    items: TopItem[];
    total: number;
    nowMs: number;
    units: Units;
    focused?: string | null;
    onpick: (key: string) => void;
    onall: () => void;
  } = $props();

  const ROWS = 5;
  const list = new StableList<TopItem>((i) => i.key, 1000, 3000);
  $effect(() => {
    const top = [...items].sort((a, b) => b.bps - a.bps).slice(0, ROWS);
    list.update(top, (a, b) => b.bps - a.bps, performance.now(), nowMs);
  });
  const max = $derived(Math.max(1, ...list.view.map((i) => i.bps)));
  const blanks = $derived(Math.max(0, ROWS - list.view.length));
</script>

<section class="card top" aria-label={title} onpointerenter={() => (list.frozen = true)} onpointerleave={() => (list.frozen = false)}>
  <div class="head">
    <h2 class="card-title">{title}</h2>
    <button type="button" class="all" onclick={onall}>All {total} →</button>
  </div>
  <ol>
    {#each list.view as it (it.key)}
      {@const r = formatRate(it.bps, units)}
      <li animate:flip={{ duration: 450 }}>
        <button type="button" class:on={focused === it.key} onclick={() => onpick(it.key)} title="Focus the gauge and chart on {it.name}">
          <i class="lvl {it.level}"></i>
          <span class="name">{it.name}{#if it.sub}<small>{it.sub}</small>{/if}</span>
          <span class="bar"><i style:transform="scaleX({it.bps / max})"></i></span>
          <span class="rate num">{r.value}<small>{r.unit}</small></span>
        </button>
      </li>
    {/each}
    {#each { length: blanks } as _, i (i)}
      <li class="blank" aria-hidden="true"></li>
    {/each}
  </ol>
</section>

<style>
  .top {
    padding: 14px 16px 10px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .all {
    border: 0;
    background: none;
    color: var(--accent-strong);
    font-weight: 600;
    font-size: 12px;
    cursor: pointer;
    padding: 2px 0;
  }
  ol {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  li {
    height: 34px;
  }
  li button {
    width: 100%;
    height: 100%;
    display: grid;
    grid-template-columns: 10px minmax(0, 1fr) 90px 92px;
    align-items: center;
    gap: 10px;
    padding: 0 8px;
    border: 0;
    border-radius: 8px;
    background: none;
    color: var(--text-primary);
    text-align: left;
    cursor: pointer;
  }
  li button:hover {
    background: var(--surface-2);
  }
  li button.on {
    background: var(--accent-wash);
  }
  li + li {
    border-top: 1px solid var(--border);
  }
  .name {
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
    font-size: 13px;
  }
  .name small {
    margin-left: 8px;
    color: var(--text-muted);
    font-size: 11.5px;
  }
  .lvl {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--level-idle, var(--text-muted));
  }
  .lvl.calm {
    background: var(--level-calm);
  }
  .lvl.busy {
    background: var(--level-busy);
  }
  .lvl.spike {
    background: var(--level-spike);
  }
  .bar {
    height: 6px;
    border-radius: 3px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .bar i {
    display: block;
    height: 100%;
    background: var(--accent);
    transform-origin: left;
    transition: transform 400ms ease;
  }
  .rate {
    text-align: right;
    font-size: 13px;
    font-variant-numeric: tabular-nums;
  }
  .rate small {
    margin-left: 4px;
    color: var(--text-muted);
    font-size: 11px;
  }
</style>
