<script lang="ts">
  /**
   * Shown on the Live page when Npcap is not installed, which is the normal
   * state of a PC that never ran a capture tool: Fishe doesn't ship Npcap
   * (its licence asks users to install it themselves). Says what it is, how
   * to get it, and looks again without a restart.
   */
  import { api, errorMessage } from "#lib/api/index.ts";
  import { session } from "#lib/stores/session.svelte.ts";

  let checking = $state(false);
  /** A check that still found nothing: say so, and where we looked. */
  let stillMissing = $state(false);
  let openError = $state<string | null>(null);

  async function open() {
    openError = null;
    try {
      await api.openNpcapSite();
    } catch (err) {
      openError = errorMessage(err);
    }
  }

  async function check() {
    checking = true;
    stillMissing = !(await session.recheckNpcap());
    checking = false;
  }
</script>

<section class="card missing" aria-labelledby="npcap-missing-title">
  <svg class="icon" viewBox="0 0 48 48" aria-hidden="true">
    <rect x="6" y="14" width="36" height="22" rx="4" />
    <path d="M14 36v5M24 36v5M34 36v5M14 14V8M34 14V8" />
    <circle cx="16" cy="25" r="2.5" />
    <path d="M24 25h11" />
  </svg>

  <div class="body">
    <h2 id="npcap-missing-title">Install Npcap to start measuring</h2>
    <p>
      Fishe reads network packets through <b>Npcap</b>, the capture driver Wireshark also uses. It is free for personal use and is not
      included with Fishe: its licence asks each user to install it themselves.
    </p>

    <ol>
      <li>Download the installer from <span class="mono">npcap.com</span>.</li>
      <li>Run it. The default options are fine.</li>
      <li>Come back and press <b>Check again</b>. No restart is needed.</li>
    </ol>

    <div class="actions">
      <button type="button" class="primary" onclick={open}>Open npcap.com</button>
      <button type="button" onclick={check} disabled={checking}>
        {#if checking}<span class="spin"></span> Checking…{:else}Check again{/if}
      </button>
      <!-- Always laid out, so the buttons don't move when the result arrives. -->
      <span class="result" role="status">
        {#if openError}
          <span class="err">{openError}. Go to https://npcap.com in your browser.</span>
        {:else if stillMissing && !checking}
          Not found yet{#if session.npcap?.dllDir}&nbsp;in <span class="mono">{session.npcap.dllDir}</span>{/if}. Finish the installer, then check again.
        {/if}
      </span>
    </div>

    <p class="note muted">
      Everything that doesn't capture still works: the Archive, Settings and agents setup.
    </p>
  </div>
</section>

<style>
  .missing {
    display: flex;
    gap: 20px;
    padding: 20px 22px;
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
    background: linear-gradient(180deg, var(--accent-wash), transparent 70%), var(--surface-1);
  }
  .icon {
    flex: none;
    width: 44px;
    height: 44px;
    margin-top: 2px;
    fill: none;
    stroke: var(--accent-strong);
    stroke-width: 2;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .body {
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  h2 {
    margin: 0;
    font-size: 16px;
    font-weight: 700;
  }
  p {
    margin: 0;
    max-width: 72ch;
    font-size: 13px;
    line-height: 1.5;
    color: var(--text-secondary);
  }
  p b,
  li b {
    color: var(--text-primary);
  }
  ol {
    margin: 0;
    padding-left: 20px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 13px;
    color: var(--text-secondary);
  }
  .mono {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-primary);
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 4px;
  }
  button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 32px;
    padding: 0 14px;
    border-radius: 8px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    color: var(--text-primary);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
  }
  button.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: #04121a;
  }
  button:disabled {
    opacity: 0.6;
    cursor: default;
  }
  .spin {
    width: 10px;
    height: 10px;
  }
  .result {
    min-height: 18px;
    font-size: 12px;
    color: var(--text-secondary);
  }
  .note {
    font-size: 12px;
  }
  @media (max-width: 700px) {
    .icon {
      display: none;
    }
  }
</style>
