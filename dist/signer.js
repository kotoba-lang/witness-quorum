/**
 * kotoba-datomic production Ed25519 signer + verifier.
 *
 * Pairs with the Python implementation in
 * ``40-engine/kotoba/crates/kotoba-kotodama/py/src/kotodama/kotoba-datomic.py`` (``make_ed25519_signer`` +
 * ``verify_ed25519_signature``). Both sides use the same canonical bytes
 * (see ``canonicalAttestationBytes`` in `./attestation.ts`), so a
 * signature produced on one side verifies on the other.
 *
 * Test code should keep using ``makeDeterministicTestSigner`` from
 * `./orchestrator.ts` — its output is 32-byte sha256 and is byte-stable
 * across re-runs, which makes integration tests reproducible. Production
 * cell-runners load their per-cell private key from macOS Keychain
 * (Python side) or from a secrets-managed env var, then call
 * ``makeEd25519CellSigner`` here on the orchestrator side when they
 * want to attest locally (e.g., the orchestrator itself is also a
 * witness cell, which is allowed by the witness-selector and useful for
 * single-process testing of the full path).
 *
 * Per kotoba-datomic SPEC §5 + ADR-2605231400.
 */
import { ed25519 } from "@noble/curves/ed25519";
/** Build a production CellSigner over an Ed25519 private key.
 *
 *  @param privateKey raw 32-byte Ed25519 seed
 *  @throws if `privateKey` is not 32 bytes
 */
export function makeEd25519CellSigner(privateKey) {
    if (privateKey.byteLength !== 32) {
        throw new Error(`Ed25519 private key must be 32 bytes, got ${privateKey.byteLength}`);
    }
    return async (canonicalBytes) => {
        return ed25519.sign(canonicalBytes, privateKey);
    };
}
/** Derive the raw 32-byte Ed25519 public key from a 32-byte seed. */
export function ed25519PublicKeyBytes(privateKey) {
    if (privateKey.byteLength !== 32) {
        throw new Error(`Ed25519 private key must be 32 bytes, got ${privateKey.byteLength}`);
    }
    return ed25519.getPublicKey(privateKey);
}
/** Third-party Ed25519 verifier — given canonical bytes, a detached
 *  signature, and the cell's published public key, returns whether the
 *  signature is valid. This is what the orchestrator runs on each
 *  attestation it collects via the witness transport. */
export function verifyEd25519Signature(canonical, signature, publicKey) {
    if (publicKey.byteLength !== 32) {
        throw new Error(`Ed25519 public key must be 32 bytes, got ${publicKey.byteLength}`);
    }
    if (signature.byteLength !== 64) {
        return false;
    }
    try {
        return ed25519.verify(signature, canonical, publicKey);
    }
    catch {
        return false;
    }
}
