# witness-quorum

`@etzhayyim/witness-quorum` — deterministic witness selection, a quorum
accept/reject/escalate decision rule, and Ed25519-signed validation-membrane
attestation production, over a pluggable witness transport (in-memory or
PDS-polling).

| Module | What it does |
|---|---|
| `witness-selector.ts` | `selectWitnesses`/`quorumGroup` — deterministic `sha256(cid) mod sorted-fleet` selection over a `FleetCell[]` |
| `quorum.ts` | `collectQuorum`/`quorumState` — pure accept/reject/escalate reducer by threshold, given a stream of `Attestation`s |
| `attestation.ts` | `produceAttestation`/`validateAgainstMembrane` — 3-layer validation membrane (schema/deterministic/policy) + Ed25519-signed attestation, parameterized by `MembraneRule` |
| `signer.ts` | `makeEd25519CellSigner`/`verifyEd25519Signature` — generic Ed25519 sign/verify helpers |
| `orchestrator.ts` | `writeWithWitnesses` — "write, then collect witness quorum" orchestrator over pluggable `WriteCapableClient`/`WitnessTransport` |
| `pds-transport.ts` | `createPdsPollingWitnessTransport` — HTTP-fan-out + PDS-polling `WitnessTransport` implementation |

Zero etzhayyim-specific coupling beyond an NSID string constant and a
`"council"` escalation label — every fleet topology, membrane rule, and
signer is a caller-supplied parameter.

## Provenance

Relocated 2026-07-01 from `etzhayyim/root:20-actors/etzhayyim-sdk/src/
kotoba-datomic/*.ts` (+ 3 dedicated test files) to `kotoba-lang/
witness-quorum` per the org-taxonomy library-placement rule
(ADR-2606302300). Design authority remains ADR-2605231400, in
`etzhayyim/root` — that ADR's own composition-spec naming is superseded by
ADR-2605262130, but ADR-2605262130 §D8 explicitly states the witness/quorum
semantics themselves are *preserved*, just claimed to be reimplemented
natively in Rust. That claim did not hold: this package is, as of the
relocation, **the only complete working implementation of this logic
anywhere in the `kotoba-lang` ecosystem** — its intended Rust successor
(`kotoba-net`/`kotoba-dht`/`kotoba-server` in `kotoba-lang/kotoba`) and its
cited Python counterpart (`kotodama.kotoba-datomic`) were both deleted in
an unrelated Rust/Python-workspace purge on 2026-07-01, before either ever
reimplemented this domain. Named `witness-quorum` (not `kotoba-datomic`,
the module's original directory name) to describe what it actually does
and avoid echoing the name of the now-deleted Rust crate.

No live consumer imports `@etzhayyim/sdk/kotoba-datomic` today (only
doc/ADR references) — `etzhayyim-sdk`'s own `src/kotoba-datomic/index.ts`
still becomes a re-export shim to honor that public API contract, matching
the pattern established by `kotoba-lang/{ipfs,checkpointer,base-l2}`.

This is a **physical move only** (TypeScript unchanged) — a CLJC port is
deferred to a later, separate task.

**`dist/` is committed** (see `kotoba-lang/pqh`'s README for the rationale).

## Development

```bash
npm install
npm test
npm run build
```

## License

Apache 2.0 + Charter Compliance Rider v3.6 (`/CHARTER-RIDER.md`).
