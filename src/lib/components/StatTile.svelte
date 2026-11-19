<script lang="ts">
  import type { Snippet } from "svelte";

  interface Props {
    label: string;
    value: string;
    unit?: string;
    sub?: string;
    /** CSS colour for the identity swatch (series tiles only). */
    swatch?: string;
    warn?: boolean;
    icon?: Snippet;
  }
  let { label, value, unit = "", sub = "", swatch, warn = false, icon }: Props = $props();
</script>

<div class="tile" class:warn>
  <div class="label">
    {#if swatch}<i class="swatch" style:background={swatch}></i>{/if}
    {#if icon}{@render icon()}{/if}
    {label}
  </div>
  <div class="value num">
    {value}{#if unit}<span class="unit">{unit}</span>{/if}
  </div>
  {#if sub}<div class="sub num">{sub}</div>{/if}
</div>

<style>
  .tile {
    padding: 14px 16px;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    min-width: 0;
  }
  .tile.warn {
    border-color: color-mix(in srgb, var(--level-busy) 50%, var(--border));
  }
  .label {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 12px;
    color: var(--text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .swatch {
    width: 10px;
    height: 10px;
    border-radius: 3px;
    flex: none;
  }
  .value {
    margin-top: 6px;
    font-size: 24px;
    font-weight: 600;
    letter-spacing: -0.01em;
    white-space: nowrap;
  }
  .unit {
    margin-left: 5px;
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
  }
  .sub {
    margin-top: 2px;
    font-size: 12px;
    color: var(--text-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
</style>
