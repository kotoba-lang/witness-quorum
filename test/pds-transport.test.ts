/**
 * Tests for the production PDS-polling WitnessTransport.
 *
 * Mocks both the HTTP fan-out (`fetch`) and the PDS read client. Verifies:
 *   - request fan-out POSTs the canonical body shape to the right endpoints
 *   - polling yields only quorumGroup-matching, never-seen attestations
 *   - subscription stops cleanly via AsyncIterator.return()
 *   - request HTTP errors throw (orchestrator can downgrade gracefully)
 *
 * The end-to-end orchestration is already covered by
 * kotoba-datomic-witnessed-write.test.ts; this file is scoped to the production
 * transport's own surface.
 */

import { describe, it, expect, vi } from "vitest";

import {
  collectQuorum,
  createPdsPollingWitnessTransport,
  fleetCell,
  selectWitnesses,
  type Attestation,
  type WitnessReadClient,
} from "../src/index.js";

// ─── fixtures ─────────────────────────────────────────────────────────

function fakeAttestation(quorumGroup: string, cellId: string, cellNode: string, overrides: Partial<Attestation> = {}): Attestation {
  return {
    v: 1,
    recordUri: "at://did:web:test/com.etzhayyim.maps.feature/abc",
    recordCid: "bafy-cid-1",
    cellId,
    cellNode,
    verdict: "accept",
    membraneVersion: "lex:1.0/rego:1.0/cell:abc",
    attestedAt: "2026-05-23T00:00:00Z",
    signature: new Uint8Array(32),
    quorumGroup,
    ...overrides,
  };
}

function staticReadClient(records: Array<{ uri: string; cid: string; value: Attestation }>): WitnessReadClient {
  return {
    async read() {
      return { records };
    },
  };
}

// ─── requestAttestation ─────────────────────────────────────────────

describe("PdsPollingTransport — requestAttestation", () => {
  it("POSTs the canonical body to the resolved endpoint", async () => {
    const fetchMock = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => {
      return new Response(null, { status: 202 });
    });
    const transport = createPdsPollingWitnessTransport({
      client: staticReadClient([]),
      attestationRepo: "did:web:test",
      requestEndpoint: (cell) => `https://${cell.node}/kotoba-datomic/attest`,
      fetch: fetchMock as unknown as typeof fetch,
    });

    const cell = fleetCell("node-0.test", "CellA");
    await transport.requestAttestation({
      cell,
      recordUri: "at://did:web:test/c/abc",
      recordCid: "bafy-1",
      record: { v: 1, hello: "world" },
      rule: {
        v: 1,
        nsid: "x.y.z",
        schemaRef: { path: "a", contentHash: "a".repeat(64) },
        policyRef: { path: "b", contentHash: "b".repeat(64) },
        cellRef: { path: "c", contentHash: "c".repeat(64) },
        quorumSize: 5,
        quorumThreshold: 3,
        registeredAt: "2026-05-23T00:00:00Z",
      },
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://node-0.test/kotoba-datomic/attest");
    expect(init?.method).toBe("POST");
    const body = JSON.parse(init?.body as string);
    expect(body.v).toBe(1);
    expect(body.recordCid).toBe("bafy-1");
    expect(body.record.hello).toBe("world");
    expect(body.rule.nsid).toBe("x.y.z");
  });

  it("merges requestHeaders into the POST", async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 202 }));
    const transport = createPdsPollingWitnessTransport({
      client: staticReadClient([]),
      attestationRepo: "did:web:test",
      requestEndpoint: () => "https://example.test/attest",
      requestHeaders: () => ({ "x-kotodama-verified": "test-token" }),
      fetch: fetchMock as unknown as typeof fetch,
    });

    await transport.requestAttestation({
      cell: fleetCell("n", "C"),
      recordUri: "at://x/y/z",
      recordCid: "bafy",
      record: {},
      rule: {
        v: 1,
        nsid: "x",
        schemaRef: { path: "a", contentHash: "a".repeat(64) },
        policyRef: { path: "b", contentHash: "b".repeat(64) },
        cellRef: { path: "c", contentHash: "c".repeat(64) },
        quorumSize: 5,
        quorumThreshold: 3,
        registeredAt: "2026-05-23T00:00:00Z",
      },
    });

    const [, init] = fetchMock.mock.calls[0];
    const headers = init?.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers["x-kotodama-verified"]).toBe("test-token");
  });

  it("throws on 4xx — orchestrator can log + treat cell as non-responsive", async () => {
    const fetchMock = vi.fn(async () => new Response("not found", { status: 404 }));
    const transport = createPdsPollingWitnessTransport({
      client: staticReadClient([]),
      attestationRepo: "did:web:test",
      requestEndpoint: () => "https://example.test/attest",
      fetch: fetchMock as unknown as typeof fetch,
    });

    await expect(
      transport.requestAttestation({
        cell: fleetCell("n", "C"),
        recordUri: "at://x/y/z",
        recordCid: "bafy",
        record: {},
        rule: {
          v: 1,
          nsid: "x",
          schemaRef: { path: "a", contentHash: "a".repeat(64) },
          policyRef: { path: "b", contentHash: "b".repeat(64) },
          cellRef: { path: "c", contentHash: "c".repeat(64) },
          quorumSize: 5,
          quorumThreshold: 3,
          registeredAt: "2026-05-23T00:00:00Z",
        },
      }),
    ).rejects.toThrow(/→ 404/);
  });
});

// ─── subscribeAttestations ──────────────────────────────────────────

describe("PdsPollingTransport — subscribeAttestations", () => {
  it("yields only quorumGroup-matching attestations", async () => {
    const target = "abc123";
    const records = [
      { uri: "at://test/c/1", cid: "bafy-1", value: fakeAttestation(target, "CellA", "n0") },
      { uri: "at://test/c/2", cid: "bafy-2", value: fakeAttestation("other", "CellB", "n0") },
      { uri: "at://test/c/3", cid: "bafy-3", value: fakeAttestation(target, "CellC", "n1") },
    ];
    const transport = createPdsPollingWitnessTransport({
      client: staticReadClient(records),
      attestationRepo: "did:web:test",
      requestEndpoint: () => "x",
      fetch: vi.fn() as unknown as typeof fetch,
      pollIntervalMs: 1,
    });

    const yielded: Attestation[] = [];
    const iter = transport.subscribeAttestations(target)[Symbol.asyncIterator]();
    yielded.push((await iter.next()).value);
    yielded.push((await iter.next()).value);
    await iter.return!();

    expect(yielded).toHaveLength(2);
    expect(yielded.map((a) => a.cellId).sort()).toEqual(["CellA", "CellC"]);
  });

  it("deduplicates by URI across polls", async () => {
    const target = "qg-dedupe";
    let pollCount = 0;
    const client: WitnessReadClient = {
      async read() {
        pollCount += 1;
        return {
          records: [
            { uri: "at://test/c/same", cid: "bafy", value: fakeAttestation(target, "CellA", "n0") },
          ],
        };
      },
    };
    const transport = createPdsPollingWitnessTransport({
      client,
      attestationRepo: "did:web:test",
      requestEndpoint: () => "x",
      fetch: vi.fn() as unknown as typeof fetch,
      pollIntervalMs: 5,
    });

    const iter = transport.subscribeAttestations(target)[Symbol.asyncIterator]();
    const first = await iter.next();
    expect(first.value.cellId).toBe("CellA");

    // Subsequent polls return the same record — should not yield again.
    // Race against a setTimeout that triggers iter.return() so we don't loop forever.
    const racer = new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 30));
    const res = await Promise.race([iter.next(), racer]);
    await iter.return!();
    expect(res).toBe("timeout"); // never yielded the dup
    expect(pollCount).toBeGreaterThan(1);
  });

  it("AsyncIterator.return() stops the polling loop cleanly", async () => {
    let pollCount = 0;
    const client: WitnessReadClient = {
      async read() {
        pollCount += 1;
        return { records: [] };
      },
    };
    const transport = createPdsPollingWitnessTransport({
      client,
      attestationRepo: "did:web:test",
      requestEndpoint: () => "x",
      fetch: vi.fn() as unknown as typeof fetch,
      pollIntervalMs: 5,
    });

    const iter = transport.subscribeAttestations("qg")[Symbol.asyncIterator]();
    // Race once so the loop has polled at least once.
    const racer = new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 20));
    await Promise.race([iter.next(), racer]);

    const beforeStop = pollCount;
    expect(beforeStop).toBeGreaterThan(0);

    const ret = await iter.return!();
    expect(ret.done).toBe(true);

    // After return(), the next() should immediately complete with done=true.
    const after = await iter.next();
    expect(after.done).toBe(true);
  });

  it("transient PDS error → backoff + retry, eventually yields", async () => {
    const target = "qg-flaky";
    let attempt = 0;
    const client: WitnessReadClient = {
      async read() {
        attempt += 1;
        if (attempt < 3) throw new Error("PDS 500");
        return {
          records: [
            { uri: "at://test/c/1", cid: "bafy", value: fakeAttestation(target, "CellA", "n0") },
          ],
        };
      },
    };
    const transport = createPdsPollingWitnessTransport({
      client,
      attestationRepo: "did:web:test",
      requestEndpoint: () => "x",
      fetch: vi.fn() as unknown as typeof fetch,
      pollIntervalMs: 5,
    });
    const iter = transport.subscribeAttestations(target)[Symbol.asyncIterator]();
    const first = await iter.next();
    await iter.return!();
    expect(first.value.cellId).toBe("CellA");
    expect(attempt).toBeGreaterThanOrEqual(3);
  });
});

// ─── integration with collectQuorum ─────────────────────────────────

describe("PdsPollingTransport ↔ collectQuorum integration", () => {
  it("collects ≥3-of-5 from polled attestation records", async () => {
    const target = "qg-integration";
    // Build a tiny fleet + select 5 witnesses for a known CID.
    const fleet = [
      fleetCell("n0", "A"),
      fleetCell("n0", "B"),
      fleetCell("n1", "A"),
      fleetCell("n1", "B"),
      fleetCell("n2", "A"),
      fleetCell("n2", "B"),
    ];
    const selected = await selectWitnesses("bafy-integration", fleet, 5);

    // Pre-stage 4 attestations from selected cells (one cell offline).
    const records = selected.slice(0, 4).map((c, i) => ({
      uri: `at://test/c/${i}`,
      cid: `bafy-${i}`,
      value: fakeAttestation(target, c.cellId, c.node),
    }));

    const transport = createPdsPollingWitnessTransport({
      client: staticReadClient(records),
      attestationRepo: "did:web:test",
      requestEndpoint: () => "x",
      fetch: vi.fn() as unknown as typeof fetch,
      pollIntervalMs: 5,
    });

    const state = await collectQuorum(
      selected,
      transport.subscribeAttestations(target),
      { quorumSize: 5, quorumThreshold: 3, timeoutMs: 500 },
    );
    expect(state.kind).toBe("witnessed");
    if (state.kind === "witnessed") {
      expect(state.matching.length).toBeGreaterThanOrEqual(3);
    }
  });
});
