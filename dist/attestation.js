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
import { quorumGroup } from "./witness-selector.js";
const acceptSchema = async (_record, _rule) => ({ layer: "schema", verdict: "accept" });
const acceptPolicy = async (_record, _rule) => ({ layer: "policy", verdict: "accept" });
const acceptDeterministic = async (_record, _rule) => ({ layer: "deterministic", verdict: "accept" });
/** Built-in basic schema validator — checks that `record` is a non-null
 *  plain object with a `v` integer field. Replaces the placeholder for
 *  apps that haven't wired a full Lexicon validator yet. */
export const minimalSchemaValidator = async (record, _rule) => {
    if (typeof record !== "object" || record === null) {
        return { layer: "schema", verdict: "reject", reason: "record is not an object" };
    }
    if (Array.isArray(record)) {
        return { layer: "schema", verdict: "reject", reason: "record must be an object, not an array" };
    }
    const v = record.v;
    if (typeof v !== "number" || !Number.isInteger(v) || v < 1) {
        return { layer: "schema", verdict: "reject", reason: "record.v must be a positive integer (lexicon format version)" };
    }
    return { layer: "schema", verdict: "accept" };
};
/** Validate a record against a membrane rule, returning the composite
 *  verdict. Pure function — no I/O. */
export async function validateAgainstMembrane(record, rule, validators = {}) {
    const schemaCheck = validators.schema ?? acceptSchema;
    const policyCheck = validators.policy ?? acceptPolicy;
    const detCheck = validators.deterministic ?? acceptDeterministic;
    const layers = [];
    const s = await schemaCheck(record, rule);
    layers.push(s);
    if (s.verdict !== "accept") {
        return { verdict: s.verdict, layers, reason: s.reason };
    }
    const p = await policyCheck(record, rule);
    layers.push(p);
    if (p.verdict !== "accept") {
        return { verdict: p.verdict, layers, reason: p.reason };
    }
    const d = await detCheck(record, rule);
    layers.push(d);
    if (d.verdict !== "accept") {
        return { verdict: d.verdict, layers, reason: d.reason };
    }
    return { verdict: "accept", layers };
}
/** Build the membraneVersion string per the lexicon spec:
 *  `lex:{semver}/rego:{semver}/cell:{git-sha-7}`. */
export function membraneVersionFor(rule) {
    const lex = rule.schemaRef.version ?? rule.schemaRef.contentHash.slice(0, 7);
    const rego = rule.policyRef.version ?? rule.policyRef.contentHash.slice(0, 7);
    const cell = rule.cellRef.version ?? rule.cellRef.contentHash.slice(0, 7);
    return `lex:${lex}/rego:${rego}/cell:${cell}`;
}
/** Canonicalize the attestation prefix for signing. Format:
 *  `${recordCid}\n${cellId}\n${verdict}\n${reason}\n${membraneVersion}\n${attestedAt}`.
 *  Stable for re-verification by anyone with the cell's public key. */
export function canonicalAttestationBytes(args) {
    const text = [
        args.recordCid,
        args.cellId,
        args.verdict,
        args.reason,
        args.membraneVersion,
        args.attestedAt,
    ].join("\n");
    return new TextEncoder().encode(text);
}
/** Cell-side: validate + sign + format an `com.etzhayyim.kotoba-datomic.attestation`. */
export async function produceAttestation(opts) {
    const verdictResult = await validateAgainstMembrane(opts.record, opts.rule, opts.validators);
    const attestedAt = opts.attestedAt ?? new Date().toISOString();
    const membraneVersion = membraneVersionFor(opts.rule);
    const reason = verdictResult.reason ?? "";
    const canonical = canonicalAttestationBytes({
        recordCid: opts.recordCid,
        cellId: opts.cell.cellId,
        verdict: verdictResult.verdict,
        reason,
        membraneVersion,
        attestedAt,
    });
    const signature = await opts.signer(canonical);
    const att = {
        v: 1,
        recordUri: opts.recordUri,
        recordCid: opts.recordCid,
        cellId: opts.cell.cellId,
        cellNode: opts.cell.node,
        verdict: verdictResult.verdict,
        reason: reason || undefined,
        membraneVersion,
        attestedAt,
        signature,
        quorumGroup: await quorumGroup(opts.recordCid),
    };
    if (verdictResult.verdict === "escalate") {
        att.escalationTarget = "council";
    }
    return att;
}
