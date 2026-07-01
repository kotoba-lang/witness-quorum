/**
 * kotoba-datomic witness quorum collection and verdict.
 *
 * Given the witness set produced by `selectWitnesses` and a stream (or batch)
 * of `com.etzhayyim.kotoba-datomic.attestation` records, decide whether the target
 * record is kotoba-datomic-witnessed, rejected, or pending escalation.
 *
 * Per kotoba-datomic SPEC §5 + ADR-2605231400.
 */

import type { FleetCell } from "./witness-selector.js";

export type Verdict = "accept" | "reject" | "escalate";

/**
 * One witness attestation. Shape matches the wire form of
 * `com.etzhayyim.kotoba-datomic.attestation`. Field names mirror the lexicon.
 */
export interface Attestation {
  v: 1;
  recordUri: string;
  recordCid: string;
  cellId: string;
  /** The node hostname or name this cell ran on (composite key in selector). */
  cellNode: string;
  verdict: Verdict;
  reason?: string;
  membraneVersion: string;
  attestedAt: string;
  signature: Uint8Array;
  quorumGroup: string;
  escalationTarget?: "council" | "membrane-amendment" | "human-review";
}

export type EscalationPolicy = "reject" | "council" | "pending";

export interface QuorumOptions {
  /** Total witnesses selected for this record. Default 5. Must match the rule's `quorumSize`. */
  quorumSize?: number;

  /** Minimum matching `accept` (or majority verdict) attestations required. Default 3. */
  quorumThreshold?: number;

  /** What to do when threshold is not met after all attestations are in. Default 'council'. */
  escalationPolicy?: EscalationPolicy;
}

export type QuorumState =
  | { kind: "witnessed"; verdict: "accept"; matching: Attestation[]; minority: Attestation[] }
  | { kind: "rejected"; verdict: "reject"; matching: Attestation[]; minority: Attestation[] }
  | { kind: "escalated"; reason: "no-threshold" | "policy"; attestations: Attestation[] }
  | { kind: "pending"; attestations: Attestation[]; remaining: number };

/**
 * Decide the quorum state for a record given the witness set and the
 * attestations gathered so far. Pure function — no I/O.
 *
 * Semantics:
 *   - Filter `attestations` to those whose (cellNode, cellId) is in the
 *     witness set. Anything else is ignored (a witness may try to attest
 *     under a wrong cell ID; the selector binding catches that).
 *   - Group by verdict. If any verdict reaches `quorumThreshold`, the
 *     record's state is decided by that majority verdict.
 *   - If the witness set is fully attested but no verdict reaches threshold:
 *     escalate per policy (default 'council').
 *   - Otherwise return 'pending' with the remaining attestation count.
 */
export function quorumState(
  witnesses: readonly FleetCell[],
  attestations: readonly Attestation[],
  opts: QuorumOptions = {},
): QuorumState {
  const quorumSize = opts.quorumSize ?? 5;
  const quorumThreshold = opts.quorumThreshold ?? 3;
  const escalationPolicy = opts.escalationPolicy ?? "council";

  if (quorumThreshold > quorumSize) {
    throw new Error(
      `kotoba-datomic: quorumThreshold ${quorumThreshold} exceeds quorumSize ${quorumSize}`,
    );
  }
  if (witnesses.length !== quorumSize) {
    throw new Error(
      `kotoba-datomic: witness set has ${witnesses.length} cells, expected quorumSize ${quorumSize}`,
    );
  }

  const witnessKeys = new Set(witnesses.map((w) => w.key));
  const eligible = attestations.filter((a) => witnessKeys.has(`${a.cellNode}::${a.cellId}`));

  const dedupedByCell = new Map<string, Attestation>();
  for (const a of eligible) {
    const key = `${a.cellNode}::${a.cellId}`;
    const prior = dedupedByCell.get(key);
    if (!prior || a.attestedAt > prior.attestedAt) {
      dedupedByCell.set(key, a);
    }
  }
  const finalAttestations = [...dedupedByCell.values()];

  const byVerdict: Record<Verdict, Attestation[]> = { accept: [], reject: [], escalate: [] };
  for (const a of finalAttestations) byVerdict[a.verdict].push(a);

  if (byVerdict.accept.length >= quorumThreshold) {
    return {
      kind: "witnessed",
      verdict: "accept",
      matching: byVerdict.accept,
      minority: [...byVerdict.reject, ...byVerdict.escalate],
    };
  }
  if (byVerdict.reject.length >= quorumThreshold) {
    return {
      kind: "rejected",
      verdict: "reject",
      matching: byVerdict.reject,
      minority: [...byVerdict.accept, ...byVerdict.escalate],
    };
  }

  const remaining = quorumSize - finalAttestations.length;
  if (remaining > 0) {
    return { kind: "pending", attestations: finalAttestations, remaining };
  }

  if (escalationPolicy === "council" || byVerdict.escalate.length > 0) {
    return { kind: "escalated", reason: "no-threshold", attestations: finalAttestations };
  }
  if (escalationPolicy === "reject") {
    return {
      kind: "rejected",
      verdict: "reject",
      matching: byVerdict.reject,
      minority: [...byVerdict.accept, ...byVerdict.escalate],
    };
  }
  return { kind: "escalated", reason: "policy", attestations: finalAttestations };
}

/**
 * Convenience: collect attestations from an async source until quorum is reached
 * or all expected witnesses have responded. The source is typically a PDS
 * subscription filtered by `quorumGroup`.
 *
 * `timeoutMs` bounds how long we wait before falling back to escalation per
 * policy. Caller is responsible for cancellation of the source iterator on
 * return.
 */
export async function collectQuorum(
  witnesses: readonly FleetCell[],
  source: AsyncIterable<Attestation>,
  opts: QuorumOptions & { timeoutMs?: number } = {},
): Promise<QuorumState> {
  const quorumSize = opts.quorumSize ?? 5;
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const deadline = Date.now() + timeoutMs;

  const collected: Attestation[] = [];
  const iter = source[Symbol.asyncIterator]();
  while (true) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = Symbol("timedOut");
    const next = await Promise.race([
      iter.next(),
      new Promise<typeof timedOut>((resolve) => {
        timer = setTimeout(() => resolve(timedOut), remaining);
      }),
    ]);
    if (timer !== undefined) clearTimeout(timer);
    if (next === timedOut) break;
    if (next.done) break;
    collected.push(next.value);
    const state = quorumState(witnesses, collected, opts);
    if (state.kind !== "pending") return state;
    if (collected.length >= quorumSize) break;
  }
  return quorumState(witnesses, collected, opts);
}
