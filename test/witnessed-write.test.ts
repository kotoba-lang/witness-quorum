/**
 * kotoba-datomic L1-witnessed write — end-to-end orchestration test.
 *
 * Exercises the full pipeline from `writeWithWitnesses(...)` through PDS
 * commit, deterministic witness selection, fan-out, cell-side membrane
 * validation, attestation production + signing, and ≥3-of-5 quorum
 * collection. All substrate I/O is mocked; the test verifies the
 * orchestrator wires the pieces together correctly, not that any
 * particular substrate backend works.
 *
 * Per kotoba-datomic SPEC §5 + ADR-2605231400 §"Implementation plan" #2-#4.
 */

import { describe, it, expect } from "vitest";

import {
  canonicalAttestationBytes,
  createInMemoryWitnessTransport,
  flattenFleet,
  makeDeterministicTestSigner,
  makeStandardCellHandler,
  membraneVersionFor,
  minimalSchemaValidator,
  produceAttestation,
  quorumGroup,
  selectWitnesses,
  validateAgainstMembrane,
  writeWithWitnesses,
  type Attestation,
  type FleetCell,
  type MembraneRule,
  type WriteCapableClient,
} from "../src/index.js";

// ─── fixtures ─────────────────────────────────────────────────────────

function mockFleet(): FleetCell[] {
  // 10 nodes × 3 cells = 30 cells, mirroring the Murakumo shape but compact.
  return flattenFleet(
    Array.from({ length: 10 }, (_, i) => ({
      hostname: `node-${i}.test`,
      cells: ["CellA", "CellB", "CellC"],
    })),
  );
}

function mockMembraneRule(nsid: string, overrides: Partial<MembraneRule> = {}): MembraneRule {
  return {
    v: 1,
    nsid,
    schemaRef: { path: "00-contracts/lexicons/test/schema.json", contentHash: "a".repeat(64), version: "1.0.0" },
    policyRef: { path: "00-contracts/policies/test/policy.rego", contentHash: "b".repeat(64), version: "1.0.0" },
    cellRef: { path: "40-engine/kotoba/crates/kotoba-kotodama/cells/test/", contentHash: "c".repeat(64), version: "abcdef0" },
    quorumSize: 5,
    quorumThreshold: 3,
    escalationPolicy: "council",
    registeredAt: "2026-05-23T00:00:00Z",
    ...overrides,
  };
}

function mockClient(records: Array<{ uri: string; cid: string; value: Record<string, unknown> }> = []): WriteCapableClient {
  let counter = 0;
  return {
    async write(opts) {
      counter += 1;
      const rkey = opts.rkey ?? `tid-${counter}`;
      const uri = `at://did:web:test.example.com/${opts.collection}/${rkey}`;
      const cid = `bafy-cid-${counter.toString().padStart(8, "0")}`;
      records.push({ uri, cid, value: opts.record });
      return { uri, cid };
    },
  };
}

// ─── tests ────────────────────────────────────────────────────────────

describe("produceAttestation", () => {
  it("emits a signed, verdict-tagged attestation matching the lexicon shape", async () => {
    const fleet = mockFleet();
    const cell = fleet[0];
    const rule = mockMembraneRule("test.example.foo");
    const att = await produceAttestation({
      recordUri: "at://did:web:test.example.com/test.example.foo/abc",
      recordCid: "bafy-cid-12345",
      record: { v: 1, hello: "world" },
      cell,
      rule,
      signer: makeDeterministicTestSigner(cell.cellId),
    });

    expect(att.v).toBe(1);
    expect(att.verdict).toBe("accept");
    expect(att.cellId).toBe(cell.cellId);
    expect(att.cellNode).toBe(cell.node);
    expect(att.recordCid).toBe("bafy-cid-12345");
    expect(att.signature).toBeInstanceOf(Uint8Array);
    expect(att.signature.byteLength).toBe(32); // sha256 size
    expect(att.membraneVersion).toBe(membraneVersionFor(rule));
    expect(att.quorumGroup).toHaveLength(16);
  });

  it("rejects when the minimal schema validator rejects", async () => {
    const fleet = mockFleet();
    const att = await produceAttestation({
      recordUri: "at://did:web:test.example.com/x/abc",
      recordCid: "bafy-bad",
      record: { hello: "no v field" }, // missing `v`
      cell: fleet[0],
      rule: mockMembraneRule("test.example.bad"),
      validators: { schema: minimalSchemaValidator },
      signer: makeDeterministicTestSigner(fleet[0].cellId),
    });
    expect(att.verdict).toBe("reject");
    expect(att.reason).toMatch(/v must be a positive integer/);
  });

  it("attaches escalationTarget when verdict is 'escalate'", async () => {
    const fleet = mockFleet();
    const att = await produceAttestation({
      recordUri: "at://did:web:test.example.com/x/abc",
      recordCid: "bafy-esc",
      record: { v: 1 },
      cell: fleet[0],
      rule: mockMembraneRule("test.example.escalate"),
      validators: {
        deterministic: async () => ({
          layer: "deterministic",
          verdict: "escalate",
          reason: "needs human review",
        }),
      },
      signer: makeDeterministicTestSigner(fleet[0].cellId),
    });
    expect(att.verdict).toBe("escalate");
    expect(att.escalationTarget).toBe("council");
  });

  it("canonical bytes are deterministic for the same inputs", () => {
    const args = {
      recordCid: "bafy",
      cellId: "Cell",
      verdict: "accept" as const,
      reason: "",
      membraneVersion: "lex:1/rego:1/cell:abc",
      attestedAt: "2026-05-23T00:00:00Z",
    };
    const a = canonicalAttestationBytes(args);
    const b = canonicalAttestationBytes(args);
    expect(a).toEqual(b);
  });
});

describe("validateAgainstMembrane", () => {
  it("layered short-circuit: schema reject → no policy/det call", async () => {
    let policyCalled = false;
    let detCalled = false;
    const result = await validateAgainstMembrane(
      { foo: "no v" },
      mockMembraneRule("x"),
      {
        schema: minimalSchemaValidator,
        policy: async () => {
          policyCalled = true;
          return { layer: "policy", verdict: "accept" };
        },
        deterministic: async () => {
          detCalled = true;
          return { layer: "deterministic", verdict: "accept" };
        },
      },
    );
    expect(result.verdict).toBe("reject");
    expect(policyCalled).toBe(false);
    expect(detCalled).toBe(false);
    expect(result.layers).toHaveLength(1);
  });

  it("all-accept produces 3 layer verdicts", async () => {
    const result = await validateAgainstMembrane(
      { v: 1 },
      mockMembraneRule("x"),
      { schema: minimalSchemaValidator },
    );
    expect(result.verdict).toBe("accept");
    expect(result.layers.map((l) => l.layer)).toEqual(["schema", "policy", "deterministic"]);
  });
});

describe("writeWithWitnesses — happy path", () => {
  it("L1-witnessed write reaches accept quorum (5-cell handler all-accept)", async () => {
    const fleet = mockFleet();
    const captured: Array<{ uri: string; cid: string; value: Record<string, unknown> }> = [];
    const client = mockClient(captured);
    const rule = mockMembraneRule("test.example.feature");

    // Pre-compute which cells will be selected for the CID we know mockClient
    // will produce (deterministic: bafy-cid-00000001). This lets us wire
    // exactly the right handlers — the production setup just registers all
    // fleet cells.
    const expectedCid = "bafy-cid-00000001";
    const selected = await selectWitnesses(expectedCid, fleet, rule.quorumSize);

    const cellHandlers = new Map(
      fleet.map((cell) => [
        cell.key,
        makeStandardCellHandler({
          cell,
          signer: makeDeterministicTestSigner(cell.cellId),
          validators: { schema: minimalSchemaValidator },
        }),
      ]),
    );
    const transport = createInMemoryWitnessTransport({ cellHandlers });

    const result = await writeWithWitnesses({
      client,
      writeOpts: {
        collection: "test.example.feature",
        record: { v: 1, label: "Mountain", name: "Fuji" },
      },
      fleet,
      rule,
      transport,
      timeoutMs: 5_000,
    });

    expect(result.cid).toBe(expectedCid);
    expect(result.selectedWitnesses).toHaveLength(5);
    expect(result.selectedWitnesses.map((c) => c.key).sort()).toEqual(
      selected.map((c) => c.key).sort(),
    );
    expect(result.state.kind).toBe("witnessed");
    if (result.state.kind === "witnessed") {
      expect(result.state.verdict).toBe("accept");
      // collectQuorum exits at threshold (3) to minimize latency, so we
      // get ≥quorumThreshold matching attestations — not necessarily all 5.
      expect(result.state.matching.length).toBeGreaterThanOrEqual(rule.quorumThreshold);
    }
    expect(captured).toHaveLength(1);
    expect(captured[0].value.label).toBe("Mountain");
  });

  it("3-of-5 quorum: 3 accept + 2 reject → witnessed accept", async () => {
    const fleet = mockFleet();
    const client = mockClient();
    const rule = mockMembraneRule("test.example.split");
    const expectedCid = "bafy-cid-00000001";
    const selected = await selectWitnesses(expectedCid, fleet, rule.quorumSize);

    // First 3 selected cells accept, last 2 reject.
    const cellHandlers = new Map<string, ReturnType<typeof makeStandardCellHandler>>();
    for (const cell of fleet) {
      const idx = selected.findIndex((s) => s.key === cell.key);
      const validators = idx === -1 || idx < 3
        ? { schema: minimalSchemaValidator }
        : {
            schema: async () => ({ layer: "schema" as const, verdict: "reject" as const, reason: "policy says no" }),
          };
      cellHandlers.set(
        cell.key,
        makeStandardCellHandler({
          cell,
          signer: makeDeterministicTestSigner(cell.cellId),
          validators,
        }),
      );
    }
    const transport = createInMemoryWitnessTransport({ cellHandlers });

    const result = await writeWithWitnesses({
      client,
      writeOpts: { collection: "test.example.split", record: { v: 1 } },
      fleet,
      rule,
      transport,
      timeoutMs: 5_000,
    });

    expect(result.state.kind).toBe("witnessed");
    if (result.state.kind === "witnessed") {
      expect(result.state.verdict).toBe("accept");
      // collectQuorum exits as soon as the 3rd accept arrives; the in-memory
      // transport delivers attestations in nondeterministic order, so 0..2 of
      // the rejecting minority may have been collected by then.
      expect(result.state.matching).toHaveLength(3);
      expect(result.state.matching.every((a) => a.verdict === "accept")).toBe(true);
      expect(result.state.minority.length).toBeLessThanOrEqual(2);
      expect(result.state.minority.every((a) => a.verdict === "reject")).toBe(true);
    }
  });
});

describe("writeWithWitnesses — rejection + escalation", () => {
  it("3-of-5 reject quorum → rejected", async () => {
    const fleet = mockFleet();
    const client = mockClient();
    const rule = mockMembraneRule("test.example.bad");
    const cellHandlers = new Map(
      fleet.map((cell) => [
        cell.key,
        makeStandardCellHandler({
          cell,
          signer: makeDeterministicTestSigner(cell.cellId),
          validators: {
            schema: async () => ({ layer: "schema" as const, verdict: "reject" as const, reason: "always reject" }),
          },
        }),
      ]),
    );
    const transport = createInMemoryWitnessTransport({ cellHandlers });

    const result = await writeWithWitnesses({
      client,
      writeOpts: { collection: "test.example.bad", record: { v: 1 } },
      fleet,
      rule,
      transport,
      timeoutMs: 5_000,
    });

    expect(result.state.kind).toBe("rejected");
  });

  it("no quorum + escalationPolicy=council → escalated", async () => {
    const fleet = mockFleet();
    const client = mockClient();
    const rule = mockMembraneRule("test.example.split-evenly");
    const expectedCid = "bafy-cid-00000001";
    const selected = await selectWitnesses(expectedCid, fleet, rule.quorumSize);

    // 2 accept + 2 reject + 1 escalate — neither verdict reaches threshold.
    const cellHandlers = new Map<string, ReturnType<typeof makeStandardCellHandler>>();
    const accept = { schema: minimalSchemaValidator };
    const reject = {
      schema: async () => ({ layer: "schema" as const, verdict: "reject" as const, reason: "no" }),
    };
    const escalate = {
      deterministic: async () => ({
        layer: "deterministic" as const,
        verdict: "escalate" as const,
        reason: "human review",
      }),
    };
    for (const cell of fleet) {
      const idx = selected.findIndex((s) => s.key === cell.key);
      let validators;
      if (idx === -1 || idx < 2) validators = accept;
      else if (idx < 4) validators = reject;
      else validators = escalate;
      cellHandlers.set(
        cell.key,
        makeStandardCellHandler({
          cell,
          signer: makeDeterministicTestSigner(cell.cellId),
          validators,
        }),
      );
    }
    const transport = createInMemoryWitnessTransport({ cellHandlers });

    const result = await writeWithWitnesses({
      client,
      writeOpts: { collection: "test.example.split-evenly", record: { v: 1 } },
      fleet,
      rule,
      transport,
      timeoutMs: 5_000,
    });

    expect(result.state.kind).toBe("escalated");
  });

  it("non-responsive cells (cellHandlers missing) → pending → escalated on timeout", async () => {
    const fleet = mockFleet();
    const client = mockClient();
    const rule = mockMembraneRule("test.example.silent");
    // Only 2 cells respond, even though 5 are selected. The other 3 are
    // simulated as offline (no handler entry).
    const expectedCid = "bafy-cid-00000001";
    const selected = await selectWitnesses(expectedCid, fleet, rule.quorumSize);
    const cellHandlers = new Map<string, ReturnType<typeof makeStandardCellHandler>>();
    for (const cell of selected.slice(0, 2)) {
      cellHandlers.set(
        cell.key,
        makeStandardCellHandler({
          cell,
          signer: makeDeterministicTestSigner(cell.cellId),
          validators: { schema: minimalSchemaValidator },
        }),
      );
    }
    const transport = createInMemoryWitnessTransport({ cellHandlers });

    const result = await writeWithWitnesses({
      client,
      writeOpts: { collection: "test.example.silent", record: { v: 1 } },
      fleet,
      rule,
      transport,
      timeoutMs: 100, // short timeout for the test
    });

    // 2 accepts < quorumThreshold (3) AND no more attestations coming →
    // the collectQuorum timeout path returns the current pending state,
    // which quorumState then reduces to "pending" (eventCount < quorumSize).
    expect(["escalated", "pending"]).toContain(result.state.kind);
  });
});

describe("writeWithWitnesses — determinism", () => {
  it("same record → same quorumGroup → same witness set across runs", async () => {
    const fleet = mockFleet();
    const record = { v: 1, label: "Mountain", name: "Fuji" };
    const cid1 = "deadbeef0001";
    const cid2 = "deadbeef0001"; // same as cid1 → same witnesses

    const ws1 = await selectWitnesses(cid1, fleet, 5);
    const ws2 = await selectWitnesses(cid2, fleet, 5);
    expect(ws1.map((c) => c.key)).toEqual(ws2.map((c) => c.key));

    const qg1 = await quorumGroup(cid1);
    const qg2 = await quorumGroup(cid2);
    expect(qg1).toBe(qg2);
  });

  it("different CIDs produce different witness sets", async () => {
    const fleet = mockFleet();
    const ws1 = await selectWitnesses("cid-a", fleet, 5);
    const ws2 = await selectWitnesses("cid-b", fleet, 5);
    // Not guaranteed completely disjoint, but should differ.
    expect(ws1.map((c) => c.key)).not.toEqual(ws2.map((c) => c.key));
  });
});

describe("Attestation shape contract", () => {
  it("attestation shape matches the wire format expected by the lexicon", async () => {
    const fleet = mockFleet();
    const cell = fleet[0];
    const att: Attestation = await produceAttestation({
      recordUri: "at://did:web:test.example.com/test.example.foo/abc",
      recordCid: "bafy-cid-12345",
      record: { v: 1, hello: "world" },
      cell,
      rule: mockMembraneRule("test.example.foo"),
      signer: makeDeterministicTestSigner(cell.cellId),
    });
    // Required fields per com.etzhayyim.kotoba-datomic.attestation lexicon
    expect(att).toHaveProperty("v");
    expect(att).toHaveProperty("recordUri");
    expect(att).toHaveProperty("recordCid");
    expect(att).toHaveProperty("cellId");
    expect(att).toHaveProperty("verdict");
    expect(att).toHaveProperty("membraneVersion");
    expect(att).toHaveProperty("attestedAt");
    expect(att).toHaveProperty("signature");
    expect(att).toHaveProperty("quorumGroup");
    // Verdict is one of the knownValues set
    expect(["accept", "reject", "escalate"]).toContain(att.verdict);
  });
});
