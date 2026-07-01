/**
 * kotoba-datomic attestation production + membrane validation (cell side).
 *
 * A Murakumo Pregel cell selected as a witness for a record calls
 * `produceAttestation` to:
 *   1. validate the record against its kotoba-datomic-membrane (3 layers: Lexicon
 *      schema / Rego policy / LangGraph determinism),
 *   2. produce a signed verdict that other parties can verify against the
 *      cell's published key, and
 *   3. format the verdict as an `com.etzhayyim.kotoba-datomic.attestation` record
 *      ready for PDS commit.
 *
 * Per kotoba-datomic SPEC §4 + §5 + ADR-2605231400.
 */
import type { Attestation, Verdict } from "./quorum.js";
import { type FleetCell } from "./witness-selector.js";
/** A reference to a membrane layer artifact, mirroring
 *  com.etzhayyim.kotoba-datomic.membraneRule#layerRef. */
export interface MembraneLayerRef {
    path: string;
    contentHash: string;
    version?: string;
}
/** A loaded membrane rule for a single NSID. Mirrors
 *  com.etzhayyim.kotoba-datomic.membraneRule. */
export interface MembraneRule {
    v: 1;
    nsid: string;
    schemaRef: MembraneLayerRef;
    policyRef: MembraneLayerRef;
    cellRef: MembraneLayerRef;
    quorumSize: number;
    quorumThreshold: number;
    escalationPolicy?: "reject" | "council" | "pending";
    ciphertextOnly?: boolean;
    registeredAt: string;
    supersedesNsid?: string;
}
/** Verdict + optional structured detail from one layer check. */
export interface LayerVerdict {
    layer: "schema" | "policy" | "deterministic";
    verdict: Verdict;
    reason?: string;
}
/** Combined verdict produced by all three layers. */
export interface MembraneVerdict {
    verdict: Verdict;
    layers: LayerVerdict[];
    /** Reason explaining the final verdict. For accept verdicts this may be
     *  empty; for reject/escalate it is the rejecting layer's reason. */
    reason?: string;
}
/** Pluggable validator for one membrane layer.
 *
 *  Default implementations are intentionally simple stubs that always
 *  accept. Real cells override these per (NSID, layer) — schema becomes a
 *  full Lexicon JSON Schema validation, policy becomes Rego eval,
 *  deterministic becomes a LangGraph cell run. */
export type SchemaValidator = (record: Record<string, unknown>, rule: MembraneRule) => Promise<LayerVerdict>;
export type PolicyValidator = (record: Record<string, unknown>, rule: MembraneRule) => Promise<LayerVerdict>;
export type DeterministicValidator = (record: Record<string, unknown>, rule: MembraneRule) => Promise<LayerVerdict>;
/** Validator triple — pass to `produceAttestation` to override defaults. */
export interface MembraneValidators {
    schema?: SchemaValidator;
    policy?: PolicyValidator;
    deterministic?: DeterministicValidator;
}
/** Built-in basic schema validator — checks that `record` is a non-null
 *  plain object with a `v` integer field. Replaces the placeholder for
 *  apps that haven't wired a full Lexicon validator yet. */
export declare const minimalSchemaValidator: SchemaValidator;
/** Validate a record against a membrane rule, returning the composite
 *  verdict. Pure function — no I/O. */
export declare function validateAgainstMembrane(record: Record<string, unknown>, rule: MembraneRule, validators?: MembraneValidators): Promise<MembraneVerdict>;
/** Sign callback — produces a detached signature over a canonical buffer.
 *  Test implementations may return a deterministic stub (e.g.,
 *  `sha256(input + cellId)`); production cells use
 *  {@link makeEd25519CellSigner}. */
export type CellSigner = (canonicalBytes: Uint8Array) => Promise<Uint8Array>;
/** Build the membraneVersion string per the lexicon spec:
 *  `lex:{semver}/rego:{semver}/cell:{git-sha-7}`. */
export declare function membraneVersionFor(rule: MembraneRule): string;
/** Canonicalize the attestation prefix for signing. Format:
 *  `${recordCid}\n${cellId}\n${verdict}\n${reason}\n${membraneVersion}\n${attestedAt}`.
 *  Stable for re-verification by anyone with the cell's public key. */
export declare function canonicalAttestationBytes(args: {
    recordCid: string;
    cellId: string;
    verdict: Verdict;
    reason: string;
    membraneVersion: string;
    attestedAt: string;
}): Uint8Array;
export interface ProduceAttestationOpts {
    /** AT URI of the record being attested. */
    recordUri: string;
    /** Content identifier of the record. */
    recordCid: string;
    /** The deserialized record value (or ciphertext envelope, for
     *  membrane.ciphertextOnly rules). */
    record: Record<string, unknown>;
    /** The witness cell producing this attestation. */
    cell: FleetCell;
    /** The membrane rule loaded for `record`'s NSID. */
    rule: MembraneRule;
    /** Per-layer validators (defaults to always-accept stubs). */
    validators?: MembraneValidators;
    /** Cell-side detached signer over the canonical attestation bytes. */
    signer: CellSigner;
    /** Override `attestedAt`; defaults to `new Date().toISOString()`. */
    attestedAt?: string;
}
/** Cell-side: validate + sign + format an `com.etzhayyim.kotoba-datomic.attestation`. */
export declare function produceAttestation(opts: ProduceAttestationOpts): Promise<Attestation>;
