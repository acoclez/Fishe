<script lang="ts">
  let { size = 28 }: { size?: number } = $props();
</script>

<!-- Fishe mark: a fish whose body carries a small gauge arc. -->
<svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
  <defs>
    <linearGradient id="fishe-body" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="var(--accent-strong)" />
      <stop offset="1" stop-color="var(--accent-deep)" />
    </linearGradient>
  </defs>
  <path
    d="M4 32 C12 17 26 13 38 15 C44 16 48 21 50 25 L61 17 L58 32 L61 47 L50 39 C48 43 44 48 38 49 C26 51 12 47 4 32 Z"
    fill="url(#fishe-body)"
  />
  <circle cx="15" cy="29" r="3" fill="var(--bg)" />
  <path d="M24 40 A11 11 0 0 1 44 36" fill="none" stroke="var(--bg)" stroke-width="3" stroke-linecap="round" />
  <path d="M33 40 L40 30" stroke="var(--bg)" stroke-width="3" stroke-linecap="round" />
</svg>
