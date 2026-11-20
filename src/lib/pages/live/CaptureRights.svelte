<script lang="ts">
  /**
   * Shown on the Live page on Linux when Fishe is not allowed to capture,
   * which is the normal state after an install: reading packets takes a
   * permission ordinary programs don't have. Fishe never raises its own
   * rights; this gives the one command that grants it, for the user to run.
   * A program's permissions are read when it starts, so there is no "check
   * again" here: the next launch has it.
   */
  import { session } from "#lib/stores/session.svelte.ts";

  const command = $derived(session.npcap?.grantCommand ?? null);
  let copied = $state(false);
  let copyError = $state(false);

  async function copy() {
    if (!command) return;
    try {
      await navigator.clipboard.writeText(command);
      copied = true;
      copyError = false;
      setTimeout(() => (copied = false), 1600);
    } catch {
      copyError = true;
    }
  }
</script>

<section class="card rights" aria-labelledby="capture-rights-title">
  <svg class="icon" viewBox="0 0 48 48" aria-hidden="true">
    <rect x="10" y="21" width="28" height="20" rx="4" />
    <path d="M16 21v-6a8 8 0 0 1 16 0v6" />
    <circle cx="24" cy="30" r="2.5" />
    <path d="M24 32.5V36" />
  </svg>

  <div class="body">
    <h2 id="capture-rights-title">Allow Fishe to capture packets</h2>
    <p>
      On Linux, reading network packets takes a permission that programs don't have by default. Fishe doesn't give it to itself: you
      grant it once, and Fishe then captures without running as root.
    </p>

    {#if command}
      <ol>
        <li>
          Run this in a terminal (it asks for your password):
          <div class="cmd">
            <code>{command}</code>
            <button type="button" onclick={copy}>{copied ? "Copied" : "Copy"}</button>
          </div>
        </li>
        <li>Close Fishe and start it again.</li>
      </ol>
      <!-- Always laid out, so nothing moves when it appears. -->
      <span class="result" role="status">{#if copyError}Couldn't reach the clipboard: select the command and copy it.{/if}</span>
      <p class="note muted">
        The permission (<span class="mono">CAP_NET_RAW</span>) belongs to this copy of Fishe only and is the one ping and traceroute need too.
        An update replaces the program, so the command is needed again after one.
      </p>
    {:else}
      <p>
        This copy of Fishe runs from a place where that permission can't be granted. Install Fishe from the <span class="mono">.deb</span>
        or <span class="mono">.rpm</span> package, or start it as root.
      </p>
    {/if}

    <p class="note muted">Everything that doesn't capture still works: the Archive, Settings and agents setup.</p>
  </div>
</section>

<style>
  .rights {
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
  ol {
    margin: 0;
    padding-left: 20px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    font-size: 13px;
    color: var(--text-secondary);
  }
  .cmd {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 6px;
    max-width: 72ch;
  }
  code {
    flex: 1;
    min-width: 0;
    padding: 7px 10px;
    border: 1px solid var(--border-strong);
    border-radius: 8px;
    background: var(--surface-2);
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-primary);
    overflow-x: auto;
    white-space: nowrap;
    user-select: all;
  }
  .mono {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-primary);
  }
  button {
    flex: none;
    /* Fixed width: "Copy" and "Copied" take the same room. */
    width: 76px;
    height: 32px;
    border-radius: 8px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    color: var(--text-primary);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
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
