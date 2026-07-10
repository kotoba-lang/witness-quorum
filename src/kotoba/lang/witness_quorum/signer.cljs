(ns kotoba.lang.witness-quorum.signer
  "nbb/ClojureScript Ed25519 signer + verifier -- portable sibling to
  signer.clj (JVM). Uses @noble/curves/ed25519 (npm), which signer.clj's
  own docstring names as the reference this repo's JVM implementation was
  verified byte-for-byte compatible with. Same public API as signer.clj
  (make-ed25519-cell-signer / ed25519-public-key-bytes /
  verify-ed25519-signature); a signature produced on one platform must
  verify on the other -- that cross-platform property is this file's
  whole reason to exist (ADR-2607110300, following up on
  kotoba-lang/murakumo#18's dial-only nbb client: the *signing* half was
  the remaining JVM-bound piece).

  Runnable via nbb (Node.js) on any fleet node -- no JVM required."
  (:require ["@noble/curves/ed25519" :refer [ed25519]]))

(defn make-ed25519-cell-signer
  "Build a signer over an Ed25519 private key (32-byte Uint8Array/Buffer).
  Returns a function `(fn [canonical-bytes] -> signature-bytes)` (64 bytes,
  Uint8Array)."
  [private-key]
  (when (not= (.-length private-key) 32)
    (throw (js/Error. (str "Ed25519 private key must be 32 bytes, got " (.-length private-key)))))
  (fn [canonical-bytes]
    (.sign ed25519 canonical-bytes private-key)))

(defn ed25519-public-key-bytes
  "Derive the raw 32-byte Ed25519 public key from a 32-byte seed."
  [private-key]
  (when (not= (.-length private-key) 32)
    (throw (js/Error. (str "Ed25519 private key must be 32 bytes, got " (.-length private-key)))))
  (.getPublicKey ed25519 private-key))

(defn verify-ed25519-signature
  "Third-party Ed25519 verifier -- given canonical bytes, a detached
  signature, and the cell's published public key, returns whether the
  signature is valid."
  [canonical signature public-key]
  (when (not= (.-length public-key) 32)
    (throw (js/Error. (str "Ed25519 public key must be 32 bytes, got " (.-length public-key)))))
  (if (not= (.-length signature) 64)
    false
    (try
      (boolean (.verify ed25519 signature canonical public-key))
      (catch :default _ false))))
