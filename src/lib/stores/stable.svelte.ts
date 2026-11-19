/**
 * Live tables that stay readable: values refresh at most once a second, the
 * order changes at most every few seconds and never while the pointer is
 * over the table (`frozen`), and new rows join at the bottom until the next
 * re-sort. A change of sort or filter applies at once (`force`).
 *
 * Rows that move are animated by the table (`animate:flip`), so a re-sort
 * reads as rows gliding, not jumping.
 */
export class StableList<T> {
  /** Rows to render. */
  view = $state.raw<T[]>([]);
  /** Session time (ms) of the data in `view`. */
  at = $state(0);
  /** Hold the order (pointer over the table). */
  frozen = $state(false);

  #order: string[] = [];
  #shownAt = -Infinity;
  #sortedAt = -Infinity;

  constructor(
    private key: (t: T) => string,
    private refreshMs = 1000,
    private resortMs = 3000,
  ) {}

  /**
   * Offer new data. `now` is a monotonic clock (ms); `t` the data's session time.
   * Returns whether `view` changed.
   */
  update(items: T[], cmp: (a: T, b: T) => number, now: number, t: number, force = false): boolean {
    if (!force && now - this.#shownAt < this.refreshMs) return false;
    this.#shownAt = now;
    this.at = t;
    const resort = force || this.#order.length === 0 || (!this.frozen && now - this.#sortedAt >= this.resortMs);
    if (resort) {
      const sorted = [...items].sort(cmp);
      this.#order = sorted.map(this.key);
      this.#sortedAt = now;
      this.view = sorted;
      return true;
    }
    const byKey = new Map(items.map((i) => [this.key(i), i]));
    const out: T[] = [];
    for (const k of this.#order) {
      const it = byKey.get(k);
      if (it !== undefined) {
        out.push(it);
        byKey.delete(k);
      }
    }
    out.push(...[...byKey.values()].sort(cmp));
    this.#order = out.map(this.key);
    this.view = out;
    return true;
  }
}
