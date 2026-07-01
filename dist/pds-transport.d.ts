/**
 * Production WitnessTransport — HTTP fan-out for requests + PDS polling
 * for attestations.
 *
 * Topology:
 *
 *   orchestrator                                cell-runner (Murakumo node)
 *   ─────────────                               ─────────────────────────────
 *       │  POST {requestEndpoint(cell)}                │
 *       │  body: { recordUri, recordCid, record, rule }│
 *       │ ─────────────────────────────────────────►   │
 *       │  202 Accepted                                │
 *       │ ◄─────────────────────────────────────────   │
 *       │                                              │
 *       │                  (cell validates membrane    │
 *       │                   + signs + writes record)   │
 *       │                                              │
 *       │             ┌────────────────────────────────┤
 *       │             ▼                                │
 *       │   PDS: com.etzhayyim.kotoba-datomic.attestation   │
 *       │  (record at attestationRepo's PDS)           │
 *       │                                              │
 *       │  GET /xrpc/com.atproto.repo.listRecords      │
 *       │  collection=com.etzhayyim.kotoba-datomic.attestation
 *       │  ──────────────────────────────────────────► │ (orchestrator's
 *       │  records[]                                   │  polling loop)
 *       │  ◄──────────────────────────────────────────│
 *       │  (filter by quorumGroup, yield new ones)     │
 *
 * Why HTTP + polling and not full atproto firehose?
 *
 *   - Lower latency for the orchestrator → witness fan-out (no polling
 *     delay on the cell side waiting for a request to materialize).
 *   - Attestations still flow through PDS (substrate-pure write/read).
 *   - Cell-runner already serves HTTP via launchd; adding a kotoba-datomic
 *     /attest endpoint is one route.
 *   - subscribeRepos firehose subscription has tail latency + memory cost
 *     proportional to all repo traffic; per-collection polling is bounded
 *     by `pollLimit × pollIntervalMs` regardless of unrelated activity.
 *
 * Cell-side contract (must be implemented by the cell-runner):
 *
 *   POST {requestEndpoint(cell)}
 *   Content-Type: application/json
 *   {
 *     "v": 1,
 *     "recordUri": "at://...",
 *     "recordCid": "bafy...",
 *     "record": { ... },
 *     "rule": { ... com.etzhayyim.kotoba-datomic.membraneRule shape ... }
 *   }
 *
 *   202 Accepted → cell will publish an
 *                  com.etzhayyim.kotoba-datomic.attestation record asynchronously.
 *   4xx/5xx     → orchestrator logs + treats this cell as non-responsive
 *                  (its share of the quorum will time out and either reduce
 *                  to a quorum-of-N-1 or escalate per rule.escalationPolicy).
 *
 * Per kotoba-datomic SPEC §5 + ADR-2605231400 §"Implementation plan" #2.
 */
import type { WitnessTransport } from "./orchestrator.js";
import type { FleetCell } from "./witness-selector.js";
/** Minimal read interface — structurally compatible with @etzhayyim/sdk
 *  Etzhayyim.read. Defining it here keeps this module decoupled from the
 *  full Etzhayyim type so tests can pass a tiny stub. */
export interface WitnessReadClient {
    read<T>(opts: {
        collection: string;
        rkey?: string;
        prefix?: string;
        limit?: number;
        cursor?: string;
        fetchBlobs?: boolean;
    }): Promise<{
        records: Array<{
            uri: string;
            cid: string;
            value: T;
        }>;
        cursor?: string;
    }>;
}
export interface PdsPollingTransportOpts {
    /** SDK client used for reading attestation records. */
    client: WitnessReadClient;
    /** DID whose PDS hosts the attestation collection. All selected cells
     *  must write their attestations to this repo. (v1 simplification —
     *  multi-DID polling is a follow-up.) */
    attestationRepo: string;
    /** Collection NSID. Default: `com.etzhayyim.kotoba-datomic.attestation`. */
    collection?: string;
    /** Per-cell HTTP endpoint that accepts the witness request POST body. */
    requestEndpoint: (cell: FleetCell) => string;
    /** Optional auth header builder — called on every requestAttestation. */
    requestHeaders?: () => Record<string, string>;
    /** Poll cadence for attestation records. Default 500 ms. */
    pollIntervalMs?: number;
    /** Max records per poll. Default 50. */
    pollLimit?: number;
    /** Per-request HTTP timeout (AbortSignal). Default 10 s. */
    requestTimeoutMs?: number;
    /** Fetch impl. Default `globalThis.fetch`. */
    fetch?: typeof fetch;
    /** Sleep impl. Default `setTimeout`. Test override only. */
    sleep?: (ms: number) => Promise<void>;
}
export declare function createPdsPollingWitnessTransport(opts: PdsPollingTransportOpts): WitnessTransport;
