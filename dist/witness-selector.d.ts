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
 * One entry from `50-infra/murakumo/fleet.toml` flattened across nodes.
 * Each cell is a (node, cellId) pair, since the same cell ID can appear on
 * multiple nodes for replication.
 */
export interface FleetCell {
    /** Murakumo node hostname (e.g., "naphtalinomac-mini.local"). */
    node: string;
    /** Cell ID — PascalCase per the fleet.toml convention (e.g., "TitheRoutingCell"). */
    cellId: string;
    /**
     * Stable composite key — `${node}::${cellId}`. Used as the selection
     * universe identity so a cell moving between nodes counts as a different
     * witness slot (intentional: the node is part of the trust assertion).
     */
    key: string;
}
/**
 * Build a FleetCell from a node + cellId. The composite `key` is derived.
 */
export declare function fleetCell(node: string, cellId: string): FleetCell;
/**
 * Quorum group identifier for a record — sha256(recordCid)[:16] hex.
 * Matches `com.etzhayyim.kotoba-datomic.attestation.quorumGroup`. Enables
 * O(1) quorum lookup by primary key once attestations land.
 */
export declare function quorumGroup(recordCid: string): Promise<string>;
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
export declare function selectWitnesses(recordCid: string, fleet: readonly FleetCell[], quorumSize?: number): Promise<FleetCell[]>;
/**
 * Flatten the fleet.toml shape `[[nodes]] cells = [...]` into a `FleetCell[]`.
 * Caller is responsible for parsing the TOML; this is the shape transformer.
 */
export declare function flattenFleet(nodes: ReadonlyArray<{
    name?: string;
    hostname?: string;
    cells: readonly string[];
}>): FleetCell[];
