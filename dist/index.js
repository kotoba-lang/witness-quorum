/**
 * @etzhayyim/sdk/kotoba-datomic
 *
 * kotoba-datomic — Holochain-isomorphic substrate composition primitives.
 * Per ADR-2605231400 + [`10-protocol/kotoba-datomic/SPEC.md`](../../../../10-protocol/kotoba-datomic/SPEC.md).
 *
 * This subpackage exposes the validation-membrane wiring (witness selection +
 * quorum collection) that complements the substrate primitives in the
 * sibling modules (`pds`, `ipfs`, `l2`, `encrypted`, `pay`).
 *
 * Status: scaffold v0.0.0. Witness cells (Murakumo Pregel cells) attest
 * out-of-band; this SDK gives apps the deterministic selection + the quorum
 * decision rule. Wiring to a live PDS subscription source is application-
 * specific (the SDK does not assume a transport).
 */
export { fleetCell, flattenFleet, quorumGroup, selectWitnesses, } from "./witness-selector.js";
export { collectQuorum, quorumState, } from "./quorum.js";
export { canonicalAttestationBytes, membraneVersionFor, minimalSchemaValidator, produceAttestation, validateAgainstMembrane, } from "./attestation.js";
export { createInMemoryWitnessTransport, makeDeterministicTestSigner, makeStandardCellHandler, writeWithWitnesses, } from "./orchestrator.js";
export { createPdsPollingWitnessTransport, } from "./pds-transport.js";
export { ed25519PublicKeyBytes, makeEd25519CellSigner, verifyEd25519Signature, } from "./signer.js";
