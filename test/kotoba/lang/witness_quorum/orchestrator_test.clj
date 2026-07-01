(ns kotoba.lang.witness-quorum.orchestrator-test
  "End-to-end orchestration test: full pipeline from `write-with-witnesses`
  through a mock PDS write, deterministic witness selection, fan-out,
  cell-side membrane validation, attestation production + signing, and
  quorum collection. All substrate I/O is mocked; verifies the orchestrator
  wires the pieces together correctly, not that any particular substrate
  backend works. Mirrors the spirit of the original TS
  test/witnessed-write.test.ts."
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.lang.witness-quorum.attestation :as attestation]
            [kotoba.lang.witness-quorum.orchestrator :as orchestrator]
            [kotoba.lang.witness-quorum.selector :as selector]))

(defn- mock-fleet []
  ;; 10 nodes x 3 cells = 30 cells, mirroring the Murakumo shape but compact.
  (selector/flatten-fleet
   (for [i (range 10)]
     {:hostname (str "node-" i ".test") :cells ["CellA" "CellB" "CellC"]})))

(defn- mock-rule [nsid & {:as overrides}]
  (merge
   {:v 1
    :nsid nsid
    :schema-ref {:path "00-contracts/lexicons/test/schema.json" :content-hash (apply str (repeat 64 "a")) :version "1.0.0"}
    :policy-ref {:path "00-contracts/policies/test/policy.rego" :content-hash (apply str (repeat 64 "b")) :version "1.0.0"}
    :cell-ref {:path "40-engine/kotoba/crates/kotoba-kotodama/cells/test/" :content-hash (apply str (repeat 64 "c")) :version "abcdef0"}
    :quorum-size 5
    :quorum-threshold 3
    :escalation-policy :council
    :registered-at "2026-05-23T00:00:00Z"}
   overrides))

(defn- mock-write-fn []
  (let [counter (atom 0)]
    (fn [write-opts]
      (let [n (swap! counter inc)
            rkey (or (:rkey write-opts) (str "tid-" n))]
        {:uri (str "at://did:web:test.example.com/" (:collection write-opts) "/" rkey)
         :cid (str "bafy-cid-" (format "%08d" n))}))))

(defn- accept-all-handlers [fleet]
  (into {} (for [cell fleet]
             [(:key cell)
              (orchestrator/make-standard-cell-handler
               {:cell cell
                :signer (orchestrator/make-deterministic-test-signer (:cell-id cell))})])))

(deftest write-with-witnesses-reaches-witnessed-test
  (testing "5-of-5 accept -> :witnessed"
    (let [fleet (mock-fleet)
          rule (mock-rule "test.example.foo")
          transport (orchestrator/create-in-memory-witness-transport
                     {:cell-handlers (accept-all-handlers fleet)})
          result (orchestrator/write-with-witnesses
                  {:write-fn (mock-write-fn)
                   :write-opts {:collection "test.example.foo" :record {:v 1 :hello "world"}}
                   :fleet fleet
                   :rule rule
                   :transport transport
                   :timeout-ms 5000})]
      (is (= 5 (count (:selected-witnesses result))))
      (is (= :witnessed (:kind (:state result))))
      (is (= :accept (:verdict (:state result))))
      (is (>= (count (:matching (:state result))) 3)))))

(deftest write-with-witnesses-reject-path-test
  (testing "cell handlers use the minimal-schema-validator and the record is missing :v -> :rejected"
    (let [fleet (mock-fleet)
          rule (mock-rule "test.example.bad")
          reject-handlers (into {} (for [cell fleet]
                                      [(:key cell)
                                       (orchestrator/make-standard-cell-handler
                                        {:cell cell
                                         :signer (orchestrator/make-deterministic-test-signer (:cell-id cell))
                                         :validators {:schema attestation/minimal-schema-validator}})]))
          transport (orchestrator/create-in-memory-witness-transport {:cell-handlers reject-handlers})
          result (orchestrator/write-with-witnesses
                  {:write-fn (mock-write-fn)
                   :write-opts {:collection "test.example.bad" :record {:hello "no v field"}}
                   :fleet fleet
                   :rule rule
                   :transport transport
                   :timeout-ms 5000})]
      (is (= :rejected (:kind (:state result)))))))

(deftest write-with-witnesses-non-responsive-cells-times-out-pending-test
  (testing "only 2 of 5 selected cells ever respond -> stays :pending until the timeout fires
            (escalation only triggers once ALL quorum-size witnesses have attested without
            reaching threshold; a handful of forever-silent cells just times out pending --
            faithful to the original TS quorumState semantics, not a bug)"
    (let [fleet (mock-fleet)
          rule (mock-rule "test.example.partial")
          write-fn (mock-write-fn)
          receipt-preview (selector/select-witnesses "bafy-cid-00000001" fleet 5)
          responsive-keys (set (map :key (take 2 receipt-preview)))
          handlers (into {} (for [cell fleet :when (contains? responsive-keys (:key cell))]
                              [(:key cell)
                               (orchestrator/make-standard-cell-handler
                                {:cell cell
                                 :signer (orchestrator/make-deterministic-test-signer (:cell-id cell))})]))
          transport (orchestrator/create-in-memory-witness-transport {:cell-handlers handlers})
          result (orchestrator/write-with-witnesses
                  {:write-fn write-fn
                   :write-opts {:collection "test.example.partial" :record {:v 1}}
                   :fleet fleet
                   :rule rule
                   :transport transport
                   :timeout-ms 500})]
      (is (= :pending (:kind (:state result))))
      (is (= 3 (:remaining (:state result)))))))
