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
import { type MembraneRule, type MembraneValidators, type CellSigner } from "./attestation.js";
import { type Attestation, type QuorumOptions, type QuorumState } from "./quorum.js";
import { type FleetCell } from "./witness-selector.js";
/** Minimal Etzhayyim shape this module depends on. Defined here so the
 *  module is callable from anywhere that has a write-capable client,
 *  including tests with mock substrate. */
export interface WriteCapableClient {
    write(opts: {
        collection: string;
        record: Record<string, unknown>;
        rkey?: string;
    }): Promise<{
        uri: string;
        cid: string;
    }>;
}
/** Per-witness call from the orchestrator side: "please attest this record".
 *  Implementations route the request to the cell (HTTP / NATS / atproto
 *  cross-actor invoke). Fire-and-forget — attestation records arrive
 *  separately on the subscription channel. */
export interface WitnessRequest {
    cell: FleetCell;
    recordUri: string;
    recordCid: string;
    record: Record<string, unknown>;
    rule: MembraneRule;
}
/** Transport abstraction. Production uses PDS XRPC (`requestAttestation`
 *  hits a per-cell endpoint, `subscribeAttestations` reads the
 *  `com.etzhayyim.kotoba-datomic.attestation` firehose filtered by `quorumGroup`).
 *  Tests use the in-memory transport in `createInMemoryWitnessTransport`. */
export interface WitnessTransport {
    requestAttestation(req: WitnessRequest): Promise<void>;
    subscribeAttestations(quorumGroup: string): AsyncIterable<Attestation>;
}
export interface WriteWithWitnessesOpts {
    client: WriteCapableClient;
    writeOpts: {
        collection: string;
        record: Record<string, unknown>;
        rkey?: string;
    };
    fleet: readonly FleetCell[];
    rule: MembraneRule;
    transport: WitnessTransport;
    /** Default: { quorumSize: rule.quorumSize, quorumThreshold: rule.quorumThreshold,
     *  escalationPolicy: rule.escalationPolicy ?? "council" }. */
    quorumOptions?: QuorumOptions;
    /** Total wall-clock budget for quorum collection. Default 30s. */
    timeoutMs?: number;
}
export interface WriteWithWitnessesResult {
    uri: string;
    cid: string;
    selectedWitnesses: FleetCell[];
    state: QuorumState;
}
/** One-shot L1-witnessed write. Returns when the quorum state is decided
 *  (witnessed / rejected / escalated) or the timeout fires. Caller is
 *  responsible for handling non-witnessed terminal states. */
export declare function writeWithWitnesses(opts: WriteWithWitnessesOpts): Promise<WriteWithWitnessesResult>;
/** Per-cell handler: given the witness request, decide whether to produce
 *  an attestation (and what verdict to issue). Returning `null` simulates
 *  a non-responsive cell. */
export type InMemoryCellHandler = (req: WitnessRequest) => Promise<Attestation | null>;
export interface InMemoryWitnessTransportOpts {
    /** Map from FleetCell.key (= `${node}::${cellId}`) to handler. Unknown
     *  cells produce no attestation (simulates cell-not-online). */
    cellHandlers: Map<string, InMemoryCellHandler>;
    /** Optional delay (ms) between requestAttestation returning and the
     *  attestation appearing on subscribeAttestations. Helps tests cover
     *  the "collect across time" path. Default 0. */
    attestationDelayMs?: number;
}
/** In-memory WitnessTransport: routes each requestAttestation to the
 *  matching cell handler, captures the produced attestation, and yields
 *  it on subscribeAttestations. The first subscriber drains the queue;
 *  subsequent subscribers see the in-flight pool. */
export declare function createInMemoryWitnessTransport(opts: InMemoryWitnessTransportOpts): WitnessTransport;
/** Test-only signer: produces a deterministic 32-byte "signature" via
 *  sha256(canonicalBytes || cellId). Replace with libsignal / Ed25519 in
 *  production cells. */
export declare function makeDeterministicTestSigner(cellId: string): CellSigner;
/** Convenience: build a default cell handler that runs the standard
 *  membrane validation pipeline and produces a signed attestation. */
export declare function makeStandardCellHandler(args: {
    cell: FleetCell;
    signer: CellSigner;
    validators?: MembraneValidators;
}): InMemoryCellHandler;
