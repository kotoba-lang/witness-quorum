/**
 * kotoba-datomic witnessed write orchestrator.
 *
 * Composes the substrate-pure write primitives (`Etzhayyim.write`, the
 * witness selector, and the quorum reducer) into a single L1-witnessed
 * write that exits the call site only when:
 *   - the record was committed to PDS, AND
 *   - ≥quorumThreshold witness cells produced matching `accept` (or
 *     `reject`) attestations.
 *
 * Per kotoba-datomic SPEC §5 + ADR-2605231400 §"Implementation plan" #2-#4.
 */
import { produceAttestation } from "./attestation.js";
import { collectQuorum } from "./quorum.js";
import { selectWitnesses } from "./witness-selector.js";
/** One-shot L1-witnessed write. Returns when the quorum state is decided
 *  (witnessed / rejected / escalated) or the timeout fires. Caller is
 *  responsible for handling non-witnessed terminal states. */
export async function writeWithWitnesses(opts) {
    const { client, writeOpts, fleet, rule, transport } = opts;
    const quorumOptions = opts.quorumOptions ?? {
        quorumSize: rule.quorumSize,
        quorumThreshold: rule.quorumThreshold,
        escalationPolicy: rule.escalationPolicy ?? "council",
    };
    // 1. PDS write — get the URI + CID. Witness selection is keyed off CID.
    const receipt = await client.write(writeOpts);
    // 2. Deterministic witness selection. Identical (cid, fleet) → identical witnesses.
    const selected = await selectWitnesses(receipt.cid, fleet, quorumOptions.quorumSize ?? rule.quorumSize);
    // 3. Fan out attestation requests. Fire-and-forget per witness; the
    //    subscription below collects the resulting attestations.
    const requests = selected.map((cell) => transport.requestAttestation({
        cell,
        recordUri: receipt.uri,
        recordCid: receipt.cid,
        record: writeOpts.record,
        rule,
    }));
    // Subscribe BEFORE awaiting the request promises so we don't miss
    // attestations that race ahead of the dispatch returns. Implementations
    // typically subscribe via PDS firehose, which is broadcast and lossless.
    const { quorumGroup } = await import("./witness-selector.js");
    const qg = await quorumGroup(receipt.cid);
    const source = transport.subscribeAttestations(qg);
    // The request dispatches must complete before we count timeouts —
    // otherwise a slow transport could starve the witness pool.
    await Promise.all(requests);
    const state = await collectQuorum(selected, source, {
        ...quorumOptions,
        timeoutMs: opts.timeoutMs ?? 30_000,
    });
    return {
        uri: receipt.uri,
        cid: receipt.cid,
        selectedWitnesses: selected,
        state,
    };
}
/** In-memory WitnessTransport: routes each requestAttestation to the
 *  matching cell handler, captures the produced attestation, and yields
 *  it on subscribeAttestations. The first subscriber drains the queue;
 *  subsequent subscribers see the in-flight pool. */
export function createInMemoryWitnessTransport(opts) {
    const queues = new Map();
    const waiters = new Map();
    return {
        async requestAttestation(req) {
            const handler = opts.cellHandlers.get(req.cell.key);
            // Fire-and-forget but capture promise so test errors surface.
            void (async () => {
                if (opts.attestationDelayMs) {
                    await new Promise((resolve) => setTimeout(resolve, opts.attestationDelayMs));
                }
                if (!handler)
                    return;
                const att = await handler(req);
                if (!att)
                    return;
                const w = waiters.get(att.quorumGroup);
                if (w && w.length > 0) {
                    const cb = w.shift();
                    if (w.length === 0)
                        waiters.delete(att.quorumGroup);
                    cb(att);
                    return;
                }
                const q = queues.get(att.quorumGroup) ?? [];
                q.push(att);
                queues.set(att.quorumGroup, q);
            })();
        },
        subscribeAttestations(quorumGroup) {
            return {
                [Symbol.asyncIterator]() {
                    return {
                        async next() {
                            const q = queues.get(quorumGroup) ?? [];
                            if (q.length > 0) {
                                const value = q.shift();
                                if (q.length === 0)
                                    queues.delete(quorumGroup);
                                return { value, done: false };
                            }
                            const att = await new Promise((resolve) => {
                                const list = waiters.get(quorumGroup) ?? [];
                                list.push(resolve);
                                waiters.set(quorumGroup, list);
                            });
                            return { value: att, done: false };
                        },
                    };
                },
            };
        },
    };
}
// ─── Deterministic test signer ─────────────────────────────────────
/** Test-only signer: produces a deterministic 32-byte "signature" via
 *  sha256(canonicalBytes || cellId). Replace with libsignal / Ed25519 in
 *  production cells. */
export function makeDeterministicTestSigner(cellId) {
    return async (canonicalBytes) => {
        const cellBytes = new TextEncoder().encode(cellId);
        const combined = new Uint8Array(canonicalBytes.length + cellBytes.length);
        combined.set(canonicalBytes, 0);
        combined.set(cellBytes, canonicalBytes.length);
        const digest = await crypto.subtle.digest("SHA-256", combined);
        return new Uint8Array(digest);
    };
}
/** Convenience: build a default cell handler that runs the standard
 *  membrane validation pipeline and produces a signed attestation. */
export function makeStandardCellHandler(args) {
    return async (req) => {
        return produceAttestation({
            recordUri: req.recordUri,
            recordCid: req.recordCid,
            record: req.record,
            cell: args.cell,
            rule: req.rule,
            validators: args.validators,
            signer: args.signer,
        });
    };
}
