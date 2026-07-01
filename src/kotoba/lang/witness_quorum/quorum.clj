(ns kotoba.lang.witness-quorum.quorum
  "Witness quorum collection and verdict.

  Given the witness set produced by `selector/select-witnesses` and a batch
  (or blocking-poll source) of attestation maps, decide whether the target
  record is witnessed, rejected, or pending escalation.

  CLJ port of this repo's original @etzhayyim/witness-quorum TypeScript
  package (src/quorum.ts). JVM-only -- see the repo README.

  Per kotoba-datomic SPEC S5 + ADR-2605231400.")

(def default-quorum-options
  {:quorum-size 5 :quorum-threshold 3 :escalation-policy :council})

(defn quorum-state
  "Decide the quorum state for a record given the witness set and the
  attestations gathered so far. Pure function -- no I/O.

  `opts` (a map, merged over `default-quorum-options`):
    :quorum-size       total witnesses selected for this record. Default 5.
                        Must match `witnesses`' count.
    :quorum-threshold  minimum matching-verdict attestations required. Default 3.
    :escalation-policy  :reject | :council | :pending. Default :council.

  Semantics:
    - Filter `attestations` to those whose (:cell-node :cell-id) is in the
      witness set. Anything else is ignored.
    - Dedup by cell, keeping the latest `:attested-at` per cell.
    - Group by :verdict. If any verdict reaches :quorum-threshold, the
      record's state is decided by that majority verdict.
    - If the witness set is fully attested but no verdict reaches
      threshold: escalate per :escalation-policy.
    - Otherwise return {:kind :pending ...} with the remaining count.

  Returns one of:
    {:kind :witnessed :verdict :accept :matching [...] :minority [...]}
    {:kind :rejected  :verdict :reject :matching [...] :minority [...]}
    {:kind :escalated :reason (:no-threshold|:policy) :attestations [...]}
    {:kind :pending :attestations [...] :remaining n}"
  ([witnesses attestations] (quorum-state witnesses attestations {}))
  ([witnesses attestations opts]
   (let [{:keys [quorum-size quorum-threshold escalation-policy]}
         (merge default-quorum-options opts)]
     (when (> quorum-threshold quorum-size)
       (throw (ex-info (str "witness-quorum: quorum-threshold " quorum-threshold " exceeds quorum-size " quorum-size)
                        {:quorum-threshold quorum-threshold :quorum-size quorum-size})))
     (when (not= (count witnesses) quorum-size)
       (throw (ex-info (str "witness-quorum: witness set has " (count witnesses) " cells, expected quorum-size " quorum-size)
                        {:witness-count (count witnesses) :quorum-size quorum-size})))
     (let [witness-keys (set (map :key witnesses))
           eligible (filter (fn [a] (contains? witness-keys (str (:cell-node a) "::" (:cell-id a))))
                             attestations)
           deduped (reduce (fn [acc a]
                              (let [k (str (:cell-node a) "::" (:cell-id a))
                                    prior (get acc k)]
                                (if (or (nil? prior) (pos? (compare (:attested-at a) (:attested-at prior))))
                                  (assoc acc k a)
                                  acc)))
                            {} eligible)
           final-attestations (vec (vals deduped))
           by-verdict (group-by :verdict final-attestations)
           accepts (get by-verdict :accept [])
           rejects (get by-verdict :reject [])
           escalates (get by-verdict :escalate [])]
       (cond
         (>= (count accepts) quorum-threshold)
         {:kind :witnessed :verdict :accept :matching accepts :minority (into rejects escalates)}

         (>= (count rejects) quorum-threshold)
         {:kind :rejected :verdict :reject :matching rejects :minority (into accepts escalates)}

         :else
         (let [remaining (- quorum-size (count final-attestations))]
           (cond
             (pos? remaining)
             {:kind :pending :attestations final-attestations :remaining remaining}

             (or (= escalation-policy :council) (seq escalates))
             {:kind :escalated :reason :no-threshold :attestations final-attestations}

             (= escalation-policy :reject)
             {:kind :rejected :verdict :reject :matching rejects :minority (into accepts escalates)}

             :else
             {:kind :escalated :reason :policy :attestations final-attestations})))))))

(defn collect-quorum
  "Collect attestations from a blocking poll source until quorum is reached
  or all expected witnesses have responded.

  This is a synchronous JVM adaptation of the original TS `collectQuorum`,
  which raced an async-iterable source against a `setTimeout`. Here
  `poll-fn` is a function of one argument (`remaining-ms`) that blocks up to
  that many milliseconds waiting for the next attestation, and returns one of:
    {:status :value :value <attestation-map>}   -- got one
    {:status :timeout}                          -- no item arrived in time
    {:status :done}                              -- source exhausted, no more ever
  (`kotoba.lang.witness-quorum.orchestrator/create-in-memory-witness-transport`
  returns a `subscribe-attestations` function producing exactly this shape,
  backed by a `java.util.concurrent.LinkedBlockingQueue`.)

  `opts` accepts the same keys as `quorum-state` plus:
    :timeout-ms  total wall-clock budget for quorum collection. Default 30000.

  Caller is responsible for any cleanup of the poll source; there is no
  cancellation signal here (unlike the TS version's iterator `.return()`)."
  ([witnesses poll-fn] (collect-quorum witnesses poll-fn {}))
  ([witnesses poll-fn opts]
   (let [timeout-ms (:timeout-ms opts 30000)
         quorum-size (:quorum-size opts (:quorum-size default-quorum-options))
         deadline (+ (System/currentTimeMillis) timeout-ms)]
     (loop [collected []]
       (let [remaining (- deadline (System/currentTimeMillis))]
         (if (<= remaining 0)
           (quorum-state witnesses collected opts)
           (let [{:keys [status value]} (poll-fn remaining)]
             (case status
               :done (quorum-state witnesses collected opts)
               :timeout (quorum-state witnesses collected opts)
               :value (let [collected' (conj collected value)
                            state (quorum-state witnesses collected' opts)]
                        (if (not= (:kind state) :pending)
                          state
                          (if (>= (count collected') quorum-size)
                            (quorum-state witnesses collected' opts)
                            (recur collected'))))))))))))
