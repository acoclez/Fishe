<script lang="ts">
  /** Network owner + country badge for an endpoint row. */
  import type { Owner } from "$lib/api/types";
  import { countryName, ownerTitle } from "$lib/utils/geo";

  let { owner }: { owner: Owner | null | undefined } = $props();
</script>

{#if owner}
  <span class="owner" title={ownerTitle(owner)}>
    {#if owner.country}<span class="cc">{owner.country}</span>{/if}
    <span class="org">{owner.org ?? (owner.asn ? `AS${owner.asn}` : countryName(owner.country))}</span>
    {#if owner.source === "ipinfo"}<span class="src" aria-label="from ipinfo.io">↗</span>{/if}
  </span>
{:else}
  <span class="none">–</span>
{/if}

<style>
  .owner {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    max-width: 220px;
    min-width: 0;
  }
  .cc {
    flex: none;
    padding: 0 5px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.04em;
    line-height: 16px;
    background: var(--surface-3);
    color: var(--text-primary);
  }
  .org {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-secondary);
    font-size: 12px;
  }
  .src {
    flex: none;
    font-size: 10px;
    color: var(--text-muted);
  }
  .none {
    color: var(--text-muted);
  }
</style>
