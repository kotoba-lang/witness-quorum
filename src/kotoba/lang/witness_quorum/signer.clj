(ns kotoba.lang.witness-quorum.signer
  "Production Ed25519 signer + verifier.

  Pairs with the Python implementation in
  `40-engine/kotoba/crates/kotoba-kotodama/py/src/kotodama/kotoba-datomic.py`
  (`make_ed25519_signer` + `verify_ed25519_signature`) and the original TS
  implementation in this repo's `src/signer.ts` (which uses
  `@noble/curves/ed25519`). All three sides use the same canonical bytes
  (see `kotoba.lang.witness-quorum.attestation/canonical-attestation-bytes`),
  so a signature produced on any side verifies on the others.

  Uses Bouncy Castle (`org.bouncycastle:bcprov-jdk18on`), NOT the JDK's
  built-in `java.security` Ed25519 KeyPairGenerator/KeyFactory -- verified
  this session that the JDK's native Ed25519 key generation does not derive
  the same public key from a raw 32-byte seed as RFC 8032 / @noble/curves
  do, even when driven through a fixed-output SecureRandom. Bouncy Castle's
  Ed25519PrivateKeyParameters/Ed25519Signer were verified byte-for-byte
  identical to @noble/curves' getPublicKey/sign for known seeds (see this
  namespace's test suite for the pinned cross-language vector).

  CLJ port of this repo's original @etzhayyim/witness-quorum src/signer.ts.
  JVM-only -- see the repo README.

  Per kotoba-datomic SPEC S5 + ADR-2605231400."
  (:import [org.bouncycastle.crypto.params Ed25519PrivateKeyParameters Ed25519PublicKeyParameters]
           [org.bouncycastle.crypto.signers Ed25519Signer]))

(defn make-ed25519-cell-signer
  "Build a production CellSigner over an Ed25519 private key.

  `private-key` a raw 32-byte Ed25519 seed (byte[]). Throws if not 32 bytes.
  Returns a function `(fn [canonical-bytes] -> signature-bytes)` (64 bytes)."
  [^bytes private-key]
  (when (not= (alength private-key) 32)
    (throw (ex-info (str "Ed25519 private key must be 32 bytes, got " (alength private-key))
                     {:length (alength private-key)})))
  (fn [^bytes canonical-bytes]
    (let [priv (Ed25519PrivateKeyParameters. private-key 0)
          signer (Ed25519Signer.)]
      (.init signer true priv)
      (.update signer canonical-bytes 0 (alength canonical-bytes))
      (.generateSignature signer))))

(defn ed25519-public-key-bytes
  "Derive the raw 32-byte Ed25519 public key from a 32-byte seed."
  [^bytes private-key]
  (when (not= (alength private-key) 32)
    (throw (ex-info (str "Ed25519 private key must be 32 bytes, got " (alength private-key))
                     {:length (alength private-key)})))
  (let [priv (Ed25519PrivateKeyParameters. private-key 0)]
    (.getEncoded (.generatePublicKey priv))))

(defn verify-ed25519-signature
  "Third-party Ed25519 verifier -- given canonical bytes, a detached
  signature, and the cell's published public key, returns whether the
  signature is valid. This is what the orchestrator runs on each
  attestation it collects via the witness transport."
  [^bytes canonical ^bytes signature ^bytes public-key]
  (when (not= (alength public-key) 32)
    (throw (ex-info (str "Ed25519 public key must be 32 bytes, got " (alength public-key))
                     {:length (alength public-key)})))
  (if (not= (alength signature) 64)
    false
    (try
      (let [pub (Ed25519PublicKeyParameters. public-key 0)
            verifier (Ed25519Signer.)]
        (.init verifier false pub)
        (.update verifier canonical 0 (alength canonical))
        (.verifySignature verifier signature))
      (catch Exception _ false))))
