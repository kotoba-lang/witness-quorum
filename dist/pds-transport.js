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
const DEFAULT_COLLECTION = "com.etzhayyim.kotoba-datomic.attestation";
const DEFAULT_POLL_INTERVAL_MS = 500;
const DEFAULT_POLL_LIMIT = 50;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
export function createPdsPollingWitnessTransport(opts) {
    const collection = opts.collection ?? DEFAULT_COLLECTION;
    const pollIntervalMs = opts.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    const pollLimit = opts.pollLimit ?? DEFAULT_POLL_LIMIT;
    const requestTimeoutMs = opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    const fetchImpl = opts.fetch ?? globalThis.fetch;
    const sleepImpl = opts.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    if (typeof fetchImpl !== "function") {
        throw new Error("createPdsPollingWitnessTransport: fetch implementation missing (no globalThis.fetch and no opts.fetch)");
    }
    return {
        async requestAttestation(req) {
            const url = opts.requestEndpoint(req.cell);
            const ac = new AbortController();
            const timer = setTimeout(() => ac.abort(), requestTimeoutMs);
            try {
                const resp = await fetchImpl(url, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        ...(opts.requestHeaders?.() ?? {}),
                    },
                    body: JSON.stringify({
                        v: 1,
                        recordUri: req.recordUri,
                        recordCid: req.recordCid,
                        record: req.record,
                        rule: req.rule,
                    }),
                    signal: ac.signal,
                });
                if (resp.status >= 400) {
                    // Best-effort body capture for logs; don't fail the orchestrator
                    // — the missing attestation will surface as a smaller quorum.
                    let body = "";
                    try {
                        body = await resp.text();
                    }
                    catch {
                        // ignore body read errors
                    }
                    throw new Error(`requestAttestation ${url} → ${resp.status}: ${body.slice(0, 200)}`);
                }
            }
            finally {
                clearTimeout(timer);
            }
        },
        subscribeAttestations(quorumGroup) {
            const seenUris = new Set();
            const buffered = [];
            let stopped = false;
            async function pollOnce() {
                const { records } = await opts.client.read({
                    collection,
                    limit: pollLimit,
                });
                for (const r of records) {
                    if (seenUris.has(r.uri))
                        continue;
                    if (r.value.quorumGroup !== quorumGroup)
                        continue;
                    seenUris.add(r.uri);
                    buffered.push(r.value);
                }
            }
            return {
                [Symbol.asyncIterator]() {
                    return {
                        async next() {
                            while (!stopped) {
                                if (buffered.length > 0) {
                                    return { value: buffered.shift(), done: false };
                                }
                                try {
                                    await pollOnce();
                                }
                                catch (err) {
                                    // Transient PDS error — back off and retry. The
                                    // collectQuorum deadline race will eventually unblock.
                                    await sleepImpl(pollIntervalMs);
                                    continue;
                                }
                                if (buffered.length === 0) {
                                    await sleepImpl(pollIntervalMs);
                                }
                            }
                            return { value: undefined, done: true };
                        },
                        async return() {
                            stopped = true;
                            return { value: undefined, done: true };
                        },
                    };
                },
            };
        },
    };
}
