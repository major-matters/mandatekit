/**
 * Usage state for the 0.2 limits.
 *
 * A mandate's `limits` (max uses, cumulative amount, per-window counts) can
 * only be enforced against a record of what the mandate has already been used
 * for. `verify()` is stateless by itself, so a mandate that declares `limits`
 * is denied unless the caller passes a store; this module holds the store
 * contract and an in-memory reference implementation.
 *
 * `recordUse()` in the verifier module writes one record for every mandate id
 * in a delegation chain (the leaf and each ancestor), so a parent's limits
 * bind all of its children. The verifier only reads; the caller records after
 * it has acted on an "allow", which keeps check and act separate, as in
 * BudgetGuard.
 *
 * Fail closed: a store that throws, or returns a malformed record, is a deny
 * (`limits_store`), never an exception out of `verify()`.
 *
 * The in-memory store is single process and per instance; a store that
 * survives a restart is roadmap work (6.3), not in 0.2.
 */

export interface Use {
  /** Seconds since the epoch (the verifier compares against its `now`). */
  at: number;
  action: string | null;
  amount: { value: number; currency: string } | null;
}

export interface UsageStore {
  uses(mandateId: string): Iterable<Use>;
  record(mandateId: string, use: Use): void;
}

/** Reference store: a map of mandate id to the list of recorded uses. */
export class InMemoryUsageStore implements UsageStore {
  private readonly data = new Map<string, Use[]>();

  uses(mandateId: string): Use[] {
    return [...(this.data.get(mandateId) ?? [])];
  }

  record(mandateId: string, use: Use): void {
    const list = this.data.get(mandateId) ?? [];
    list.push({ ...use });
    this.data.set(mandateId, list);
  }

  clear(): void {
    this.data.clear();
  }
}
