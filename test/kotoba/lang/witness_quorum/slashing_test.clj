(ns kotoba.lang.witness-quorum.slashing-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.lang.witness-quorum.reputation :as reputation]
            [kotoba.lang.witness-quorum.slashing :as slashing]
            [kotoba.lang.witness-quorum.stake :as stake]))

(def quorum-state
  {:kind :witnessed
   :matching [{:cell-node "a" :cell-id "w"} {:cell-node "b" :cell-id "w"}]
   :minority [{:cell-node "c" :cell-id "w"}]})

(deftest matching-cells-get-reputation-only-no-stake-change
  (let [initial-ledger (-> stake/empty-ledger (stake/post-bond "a::w" 100) (stake/post-bond "b::w" 100))
        {:keys [reputation-db stake-ledger]}
        (slashing/apply-quorum-outcome reputation/empty-reputation initial-ledger quorum-state 10)]
    (is (== 1.0 (reputation/score reputation-db "a::w")))
    (is (== 1.0 (reputation/score reputation-db "b::w")))
    (is (= 100 (stake/balance stake-ledger "a::w")) "matching cell's stake untouched")
    (is (= 100 (stake/balance stake-ledger "b::w")) "matching cell's stake untouched")))

(deftest minority-cells-get-reputation-penalty-and-stake-slashed
  (let [initial-ledger (stake/post-bond stake/empty-ledger "c::w" 100)
        {:keys [reputation-db stake-ledger slashed]}
        (slashing/apply-quorum-outcome reputation/empty-reputation initial-ledger quorum-state 30)]
    (is (== 0.0 (reputation/score reputation-db "c::w")))
    (is (= 70 (stake/balance stake-ledger "c::w")))
    (is (= [{:cell-key "c::w" :slashed 30}] slashed))))

(deftest slash-clamps-when-a-minority-cell-has-insufficient-stake
  (let [initial-ledger (stake/post-bond stake/empty-ledger "c::w" 5)
        {:keys [stake-ledger slashed]}
        (slashing/apply-quorum-outcome reputation/empty-reputation initial-ledger quorum-state 30)]
    (is (= 0 (stake/balance stake-ledger "c::w")))
    (is (= [{:cell-key "c::w" :slashed 5}] slashed)
        "slashed only what the cell actually had, not the full requested amount")))

(deftest unbonded-minority-cell-loses-nothing-but-still-reputation-penalized
  (let [{:keys [reputation-db slashed]}
        (slashing/apply-quorum-outcome reputation/empty-reputation stake/empty-ledger quorum-state 30)]
    (is (== 0.0 (reputation/score reputation-db "c::w")))
    (is (= [{:cell-key "c::w" :slashed 0}] slashed))))

(deftest no-minority-means-no-slashing
  (let [clean-state {:kind :witnessed :matching [{:cell-node "a" :cell-id "w"}] :minority []}
        {:keys [slashed]}
        (slashing/apply-quorum-outcome reputation/empty-reputation stake/empty-ledger clean-state 10)]
    (is (empty? slashed))))

(deftest repeated-disagreement-compounds-both-penalties
  (testing "a witness that repeatedly disagrees gets progressively worse reputation AND
            keeps losing stake round after round -- the two mechanisms actually connected"
    (let [ledger (stake/post-bond stake/empty-ledger "c::w" 100)
          round1 (slashing/apply-quorum-outcome reputation/empty-reputation ledger quorum-state 10)
          round2 (slashing/apply-quorum-outcome (:reputation-db round1) (:stake-ledger round1) quorum-state 10)
          round3 (slashing/apply-quorum-outcome (:reputation-db round2) (:stake-ledger round2) quorum-state 10)]
      (is (== 0.0 (reputation/score (:reputation-db round3) "c::w")))
      (is (= 70 (stake/balance (:stake-ledger round3) "c::w")) "100 - 10 - 10 - 10 = 70"))))
