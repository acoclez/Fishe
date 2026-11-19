<script lang="ts">
  import type { Level } from "$lib/api/types";

  let { level, size = "md" }: { level: Level; size?: "sm" | "md" } = $props();

  const LABELS: Record<Level, string> = {
    idle: "Idle",
    calm: "Calm",
    busy: "Busy",
    spike: "Spike",
  };
</script>

<!-- Level is never conveyed by colour alone: icon + label always accompany it. -->
<span class="badge {size}" style:--c="var(--level-{level})" data-level={level}>
  <svg viewBox="0 0 16 16" aria-hidden="true">
    {#if level === "idle"}
      <path d="M3 8h10" />
    {:else if level === "calm"}
      <path d="M2 9c2-3 4-3 6 0s4 3 6 0" />
    {:else if level === "busy"}
      <path d="M2 6c2-3 4-3 6 0s4 3 6 0M2 11c2-3 4-3 6 0s4 3 6 0" />
    {:else}
      <path d="M9 1 4 9h4l-1 6 5-8H8z" class="fill" />
    {/if}
  </svg>
  {LABELS[level]}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px 3px 8px;
    border-radius: 999px;
    font-weight: 600;
    color: var(--text-primary);
    background: color-mix(in srgb, var(--c) 18%, transparent);
    border: 1px solid color-mix(in srgb, var(--c) 55%, transparent);
    transition: background 300ms, border-color 300ms;
  }
  .badge.sm {
    font-size: 12px;
    padding: 1px 8px 1px 6px;
  }
  svg {
    width: 14px;
    height: 14px;
    fill: none;
    stroke: var(--c);
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .fill {
    fill: var(--c);
    stroke: none;
  }
  /*
   * Spike pulse: an opacity animation on its own layer (compositor only).
   * Animating box-shadow repainted every frame and, with a table of spiking
   * rows, kept the renderer busy ~40% of the time. Table badges (sm) don't
   * pulse at all.
   */
  .badge {
    position: relative;
  }
  .badge.md[data-level="spike"]::after {
    content: "";
    position: absolute;
    inset: -4px;
    border-radius: inherit;
    background: color-mix(in srgb, var(--c) 22%, transparent);
    opacity: 0;
    will-change: opacity;
    animation: pulse 1.2s ease-in-out infinite;
    pointer-events: none;
  }
  @keyframes pulse {
    50% {
      opacity: 1;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .badge.md[data-level="spike"]::after {
      animation: none;
    }
  }
</style>
