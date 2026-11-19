<script lang="ts">
  /** Modal confirmation for destructive actions. Esc / backdrop cancel. */
  import type { Snippet } from "svelte";

  interface Props {
    title: string;
    confirmLabel: string;
    danger?: boolean;
    busy?: boolean;
    onconfirm: () => void;
    oncancel: () => void;
    children: Snippet;
  }
  let { title, confirmLabel, danger = false, busy = false, onconfirm, oncancel, children }: Props = $props();

  let dialog: HTMLDialogElement;
  $effect(() => {
    dialog.showModal();
    return () => dialog.close();
  });
</script>

<dialog
  bind:this={dialog}
  oncancel={(e) => {
    e.preventDefault();
    oncancel();
  }}
  onclick={(e) => e.target === dialog && oncancel()}
  aria-labelledby="confirm-title"
>
  <div class="box">
    <h2 id="confirm-title">{title}</h2>
    <div class="body">{@render children()}</div>
    <div class="actions">
      <button type="button" class="cancel" onclick={oncancel} disabled={busy}>Cancel</button>
      <button type="button" class="ok" class:danger onclick={onconfirm} disabled={busy}>{busy ? "Working…" : confirmLabel}</button>
    </div>
  </div>
</dialog>

<style>
  dialog {
    padding: 0;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-lg);
    background: var(--surface-1);
    color: var(--text-primary);
    max-width: 440px;
    width: calc(100% - 32px);
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.6);
  }
  dialog::backdrop {
    background: rgba(5, 8, 10, 0.7);
  }
  .box {
    padding: 20px 22px 18px;
  }
  h2 {
    margin: 0 0 10px;
    font-size: 16px;
  }
  .body {
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.5;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-top: 18px;
  }
  button {
    height: 34px;
    padding: 0 16px;
    border-radius: 8px;
    border: 1px solid var(--border-strong);
    background: var(--surface-2);
    cursor: pointer;
    font-weight: 600;
  }
  .ok {
    background: var(--accent);
    border-color: var(--accent);
    color: #04121a;
  }
  .ok.danger {
    background: var(--danger);
    border-color: var(--danger);
    color: #fff;
  }
  button:disabled {
    opacity: 0.5;
    cursor: default;
  }
</style>
