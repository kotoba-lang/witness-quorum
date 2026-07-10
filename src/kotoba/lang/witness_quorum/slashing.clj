(ns kotoba.lang.witness-quorum.slashing
  "Connects reputation tracking (reputation.clj) with stake accounting
  (stake.clj) -- ADR-2607110300 Phase 4. Independently, neither module
  has economic teeth: reputation.clj only ever affects future selection
  eligibility (eligible-fleet), and stake.clj's post-bond/slash! are
  never called by anything. This namespace is the missing connection:
  when a quorum decision is reached, witnesses in the MINORITY
  (disagreed with the majority verdict) are both reputation-penalized
  AND have their staked bond actually slashed."
  (:require [kotoba.lang.witness-quorum.reputation :as reputation]
            [kotoba.lang.witness-quorum.stake :as stake]))

(defn- cell-key [a] (str (:cell-node a) "::" (:cell-id a)))

(defn apply-quorum-outcome
  "Given a decided quorum-state (`{:kind :witnessed|:rejected :matching
  [...] :minority [...]}`, per
  kotoba.lang.witness-quorum.quorum/quorum-state), update BOTH
  `reputation-db` and `stake-ledger` for every participating cell in one
  pass:
    - :matching cells: reputation +1 correct. No stake change -- being
      right doesn't earn a reward here, only being wrong costs (matches
      stake.clj's own scope: an accounting SHAPE, not a currency with a
      reward-emission policy this ADR hasn't designed).
    - :minority cells: reputation +1 incorrect, AND `slash-amount` bond
      units removed from their stake.

  `:pending`/`:escalated` quorum-states should NOT be passed here (not a
  decision -- same caveat reputation/record-quorum-outcomes already
  documents).

  Returns `{:reputation-db db' :stake-ledger ledger' :slashed [{:cell-key
  ... :slashed n} ...]}` -- `:slashed` is the audit trail of what
  changed and by how much this round."
  [reputation-db stake-ledger quorum-state slash-amount]
  (let [reputation-db' (reputation/record-quorum-outcomes reputation-db quorum-state)
        minority-keys (map cell-key (:minority quorum-state))]
    (reduce (fn [acc k]
              (let [{:keys [ledger slashed]} (stake/slash! (:stake-ledger acc) k slash-amount)]
                (-> acc
                    (assoc :stake-ledger ledger)
                    (update :slashed conj {:cell-key k :slashed slashed}))))
            {:reputation-db reputation-db' :stake-ledger stake-ledger :slashed []}
            minority-keys)))
