/**
 * kotoba-datomic witness selection.
 *
 * Deterministic Holochain-iso validator selection: given a record's CID and
 * the Murakumo fleet's cell catalog, return the `quorumSize` cells that will
 * attest to the record. Same CID → same cells, every time.
 *
 * Per kotoba-datomic SPEC §5 + ADR-2605231400.
 */
/**
 * Build a FleetCell from a node + cellId. The composite `key` is derived.
 */
export function fleetCell(node, cellId) {
    return { node, cellId, key: `${node}::${cellId}` };
}
/**
 * Quorum group identifier for a record — sha256(recordCid)[:16] hex.
 * Matches `com.etzhayyim.kotoba-datomic.attestation.quorumGroup`. Enables
 * O(1) quorum lookup by primary key once attestations land.
 */
export async function quorumGroup(recordCid) {
    const digest = await sha256Hex(recordCid);
    return digest.slice(0, 16);
}
/**
 * Select `quorumSize` witnesses for a record from the fleet.
 *
 * Algorithm:
 *   1. Sort the fleet by composite key (stable selection universe).
 *   2. Compute sha256(recordCid) as a 256-bit integer.
 *   3. Step through the sorted fleet starting at offset (hash mod fleetLen)
 *      and take the next `quorumSize` distinct cells (wrapping).
 *
 * Properties:
 *   - Deterministic — same (recordCid, fleet) → same witnesses.
 *   - Stable under fleet reordering (we sort first).
 *   - Unbiased — sha256 makes the offset uniform over the fleet.
 *   - Re-validatable — anyone with the fleet snapshot can re-derive the
 *     witness set from the record CID alone.
 *
 * Throws if the fleet has fewer cells than `quorumSize`.
 */
export async function selectWitnesses(recordCid, fleet, quorumSize = 5) {
    if (fleet.length < quorumSize) {
        throw new Error(`kotoba-datomic: fleet has ${fleet.length} cells, cannot select quorum of ${quorumSize}`);
    }
    if (quorumSize < 1) {
        throw new Error(`kotoba-datomic: quorumSize must be ≥1, got ${quorumSize}`);
    }
    const sorted = [...fleet].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    const digest = await sha256Hex(recordCid);
    const offset = hexToBigInt(digest) % BigInt(sorted.length);
    const selected = [];
    const seen = new Set();
    for (let i = 0; selected.length < quorumSize; i++) {
        const idx = Number((offset + BigInt(i)) % BigInt(sorted.length));
        const cell = sorted[idx];
        if (!seen.has(cell.key)) {
            selected.push(cell);
            seen.add(cell.key);
        }
        if (i >= sorted.length * 2) {
            throw new Error(`kotoba-datomic: witness selection loop did not converge — fleet may have duplicate keys`);
        }
    }
    return selected;
}
/**
 * Flatten the fleet.toml shape `[[nodes]] cells = [...]` into a `FleetCell[]`.
 * Caller is responsible for parsing the TOML; this is the shape transformer.
 */
export function flattenFleet(nodes) {
    const out = [];
    for (const node of nodes) {
        const nodeKey = node.hostname ?? node.name;
        if (!nodeKey) {
            throw new Error(`kotoba-datomic: fleet node missing both 'name' and 'hostname'`);
        }
        for (const cellId of node.cells) {
            out.push(fleetCell(nodeKey, cellId));
        }
    }
    return out;
}
// ─── internal ────────────────────────────────────────────────────────
async function sha256Hex(input) {
    const bytes = new TextEncoder().encode(input);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}
function hexToBigInt(hex) {
    return BigInt("0x" + hex);
}
