<script lang="ts">
  /**
   * Settings → Agents (MCP): let AI agents read Fishe's measurements over
   * the Model Context Protocol, and optionally drive it. Off by default;
   * local only; token required; every call is listed here.
   *
   * Layout: switch + status on top; access level (left) and how to connect a
   * client (right) side by side; activity underneath.
   */
  import { onMount } from "svelte";
  import { agents } from "#lib/stores/agents.svelte.ts";
  import type { McpAccess } from "#lib/api/types.ts";
  import ConfirmDialog from "../../components/ConfirmDialog.svelte";

  const LEVELS: { id: McpAccess; label: string; hint: string }[] = [
    { id: "read", label: "Read only", hint: "Measurements, recordings, traces, pings" },
    { id: "control", label: "+ Control", hint: "Start/stop monitoring and recording" },
    { id: "network", label: "+ Network probes", hint: "Traceroute and ping (sends packets)" },
  ];
  type Tab = "claude-code" | "desktop" | "other";
  const TABS: { id: Tab; label: string }[] = [
    { id: "claude-code", label: "Claude Code" },
    { id: "desktop", label: "Claude Desktop" },
    { id: "other", label: "Other clients" },
  ];

  let port = $state(47823);
  let showToken = $state(false);
  let confirmToken = $state(false);
  let tab = $state<Tab>("claude-code");
  let copied = $state<string | null>(null);

  onMount(async () => {
    await agents.refresh();
    if (agents.status) port = agents.status.port;
  });

  const st = $derived(agents.status);
  const token = $derived(st?.token ?? "");
  /** What is displayed: the token stays hidden everywhere until Show. */
  const tokenText = $derived(showToken ? token : "•".repeat(16) + token.slice(-4));

  function apply(enabled = st?.enabled ?? false, access = st?.access ?? "read") {
    agents.configure(enabled, access, Number(port) || 47823);
  }

  /** The configuration file content for the selected client. */
  function snippetFor(t: string) {
    if (!st) return "";
    switch (tab) {
      case "claude-code":
      case "other":
        return JSON.stringify({ mcpServers: { fishe: { type: "http", url: st.url, headers: { Authorization: `Bearer ${t}` } } } }, null, 2);
      case "desktop":
        return JSON.stringify({ mcpServers: { fishe: { command: st.exePath ?? "fishe.exe", args: ["--mcp-stdio"] } } }, null, 2);
    }
  }
  /** The same for Claude Code, as a CLI command (if `claude` is installed). */
  const cliFor = (t: string) => (st ? `claude mcp add --transport http fishe ${st.url} --header "Authorization: Bearer ${t}"` : "");
  const shownSnippet = $derived(snippetFor(tokenText));

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      copied = what;
      setTimeout(() => (copied = null), 1500);
    } catch {
      copied = null;
    }
  }

  const time = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
</script>

<div class="agents">
  <div class="top">
    <div class="title">
      <h2 class="card-title">Agents (MCP)</h2>
      <p class="muted">Let AI agents read Fishe's measurements over the Model Context Protocol. This PC only, token required.</p>
    </div>
    <span class="pill" class:on={st?.running} class:bad={!!st?.error} title={st?.error ?? st?.url ?? ""}>
      {#if st?.error}Error{:else if st?.running}<i></i>Listening · {st.calls} call{st.calls === 1 ? "" : "s"}{:else}Off{/if}
    </span>
  </div>

  <label class="switch">
    <input type="checkbox" checked={st?.enabled ?? false} disabled={!st || agents.busy} onchange={(e) => apply((e.currentTarget as HTMLInputElement).checked)} />
    <span>Allow agents to connect</span>
  </label>
  {#if st?.error}<p class="err small">{st.error}</p>{/if}

  <div class="cols">
    <fieldset class="box">
      <legend>Access</legend>
      {#each LEVELS as l (l.id)}
        <label class="level" class:on={st?.access === l.id}>
          <input type="radio" name="mcp-access" checked={st?.access === l.id} disabled={!st || agents.busy} onchange={() => apply(st?.enabled, l.id)} />
          <span class="lv">
            <b>{l.label}</b>
            <small>{l.hint}</small>
          </span>
        </label>
      {/each}
      <p class="muted small">Each level includes the ones above it. Changes apply at once.</p>
    </fieldset>

    <fieldset class="box" class:dim={!st?.enabled}>
      <legend>Connect a client</legend>
      <div class="kv">
        <label for="mcp-port">Port</label>
        <input id="mcp-port" class="port" type="number" min="1024" max="65535" bind:value={port} onchange={() => apply()} disabled={!st} />
        <span class="muted url mono">{st?.url ?? ""}</span>
      </div>
      <div class="kv">
        <span class="lbl">Token</span>
        <code class="mono token">{tokenText}</code>
        <div class="btns">
          <button type="button" onclick={() => (showToken = !showToken)}>{showToken ? "Hide" : "Show"}</button>
          <button type="button" onclick={() => copy(token, "token")}>{copied === "token" ? "Copied" : "Copy"}</button>
          <button type="button" onclick={() => (confirmToken = true)} title="Revoke this token and make a new one">New</button>
        </div>
      </div>

      <div class="snip">
        <div class="tabs" role="tablist" aria-label="Client">
          {#each TABS as t (t.id)}
            <button type="button" role="tab" aria-selected={tab === t.id} class:on={tab === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
          {/each}
          <button type="button" class="copy" onclick={() => copy(snippetFor(token), "snippet")} title="Copies it with the real token">
            {copied === "snippet" ? "Copied" : "Copy"}
          </button>
        </div>
        <pre class="mono">{shownSnippet}</pre>
        <div class="how muted small">
          {#if tab === "claude-code"}
            <p>
              Save this as <span class="mono">.mcp.json</span> in the folder you open in Claude Code (the desktop app's Code tab or the
              terminal), then start a new session there and approve <b>fishe</b> when asked. Keep the file out of git (it holds the token).
            </p>
            <div class="alt">
              With the <span class="mono">claude</span> command installed, this does the same for every folder:
              <button type="button" onclick={() => copy(cliFor(token), "cli")}>{copied === "cli" ? "Copied" : "Copy command"}</button>
            </div>
          {:else if tab === "desktop"}
            <p>
              In Claude Desktop: <b>Settings → Developer → Edit Config</b>, merge this into
              <span class="mono">claude_desktop_config.json</span>, then restart Claude Desktop. It starts Fishe's stdio bridge, which reads
              the port and token from Fishe's <span class="mono">mcp.json</span>, so no token here. Fishe must be running.
            </p>
          {:else}
            <p>
              Any MCP client that supports HTTP servers: URL <span class="mono">{st?.url}</span> with the header
              <span class="mono">Authorization: Bearer &lt;token&gt;</span>. Clients that only launch commands: use the Claude Desktop entry.
            </p>
          {/if}
        </div>
      </div>
    </fieldset>
  </div>

  <div class="log">
    <div class="log-head">
      <h3>Activity{#if agents.activity.length}&nbsp;<span class="muted">· {agents.activity.length}</span>{/if}</h3>
      {#if agents.activity.length}<button type="button" class="link" onclick={() => agents.clear()}>Clear</button>{/if}
    </div>
    {#if agents.activity.length === 0}
      <p class="muted small">No agent calls yet.</p>
    {:else}
      <div class="log-body">
        <table>
          <colgroup><col class="c-t" /><col class="c-c" /><col class="c-tool" /><col /><col class="c-d" /><col class="c-r" /></colgroup>
          <tbody>
            {#each agents.activity.slice(0, 50) as a, i (a.atMs + ":" + i)}
              <tr class:err={!a.ok}>
                <td class="num muted">{time.format(new Date(a.atMs))}</td>
                <td class="muted" title={a.client}>{a.client}</td>
                <td class="mono" title={a.tool}><b>{a.tool}</b></td>
                <td class="mono muted" title={a.args}>{a.args}</td>
                <td class="num muted r">{a.durationMs} ms</td>
                <td class="note" title={a.note}>{a.ok ? "ok" : a.note}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
  {#if agents.error}<p class="err small">{agents.error}</p>{/if}
</div>

{#if confirmToken}
  <ConfirmDialog
    title="Replace the agent token?"
    confirmLabel="Replace token"
    onconfirm={() => {
      confirmToken = false;
      agents.newToken();
    }}
    oncancel={() => (confirmToken = false)}
  >
    <p>Agents configured with the current token will be refused until you give them the new one.</p>
  </ConfirmDialog>
{/if}

<style>
  .agents {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .top {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
  }
  .title p {
    margin: 4px 0 0;
  }
  .muted {
    font-size: 12px;
  }
  .small {
    margin: 0;
    font-size: 11.5px;
    line-height: 1.4;
  }
  .pill {
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 999px;
    border: 1px solid var(--border-strong);
    color: var(--text-muted);
    font-size: 12px;
    font-weight: 600;
    white-space: nowrap;
  }
  .pill.on {
    border-color: var(--accent);
    color: var(--accent-strong);
    background: var(--accent-wash);
  }
  .pill.on i {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--accent-strong);
  }
  .pill.bad {
    border-color: var(--danger);
    color: var(--danger);
  }
  .switch {
    display: inline-flex;
    align-items: center;
    gap: 9px;
    font-weight: 600;
    cursor: pointer;
    align-self: flex-start;
  }
  .switch input {
    width: 16px;
    height: 16px;
    accent-color: var(--accent);
  }
  .cols {
    display: grid;
    grid-template-columns: minmax(240px, 1fr) minmax(0, 2fr);
    gap: 14px;
    align-items: start;
  }
  .box {
    margin: 0;
    min-width: 0;
    padding: 10px 14px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .box.dim {
    opacity: 0.65;
  }
  legend {
    padding: 0 6px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .level {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    padding: 7px 9px;
    border-radius: 8px;
    border: 1px solid transparent;
    cursor: pointer;
  }
  .level:hover {
    background: var(--surface-2);
  }
  .level.on {
    border-color: color-mix(in srgb, var(--accent) 55%, transparent);
    background: var(--accent-wash);
  }
  .level input {
    margin-top: 2px;
    accent-color: var(--accent);
  }
  .lv {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
  }
  .lv small {
    color: var(--text-muted);
    font-size: 11.5px;
  }
  .kv {
    display: grid;
    grid-template-columns: 48px auto 1fr;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }
  .kv label,
  .kv .lbl {
    font-size: 12px;
    color: var(--text-secondary);
  }
  .port {
    width: 92px;
    height: 30px;
    padding: 0 8px;
    border-radius: 7px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    font-size: 13px;
  }
  .url {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .kv:has(.token) {
    grid-template-columns: 48px minmax(0, 1fr) auto;
  }
  .token {
    min-width: 0;
    padding: 5px 9px;
    border-radius: 7px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    font-size: 12px;
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .btns {
    display: flex;
    gap: 6px;
  }
  button {
    height: 28px;
    padding: 0 10px;
    border-radius: 7px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
  }
  button:hover:not(:disabled) {
    border-color: var(--accent);
  }
  .snip {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin-top: 2px;
  }
  .tabs {
    display: flex;
    gap: 4px;
  }
  .tabs button.on {
    background: var(--surface-3);
    border-color: var(--accent);
    color: var(--text-primary);
  }
  .tabs .copy {
    margin-left: auto;
  }
  .how {
    display: flex;
    flex-direction: column;
    gap: 6px;
    line-height: 1.45;
  }
  .how p {
    margin: 0;
  }
  .alt {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .alt button {
    height: 24px;
    font-size: 11.5px;
  }
  pre {
    margin: 0;
    padding: 9px 11px;
    border-radius: 8px;
    background: var(--bg);
    border: 1px solid var(--border);
    font-size: 12px;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 240px;
    overflow: auto;
  }
  .log h3 {
    margin: 0;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .log-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 6px;
  }
  .link {
    height: auto;
    border: 0;
    background: none;
    color: var(--accent-strong);
    padding: 0;
  }
  .log-body {
    max-height: 220px;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    table-layout: fixed;
  }
  td {
    padding: 5px 9px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  tr:last-child td {
    border-bottom: 0;
  }
  .c-t {
    width: 72px;
  }
  .c-c {
    width: 120px;
  }
  .c-tool {
    width: 150px;
  }
  .c-d {
    width: 64px;
  }
  .c-r {
    width: 26%;
  }
  .r {
    text-align: right;
  }
  tr.err .note {
    color: var(--danger);
  }
  @media (max-width: 980px) {
    .cols {
      grid-template-columns: 1fr;
    }
  }
</style>
