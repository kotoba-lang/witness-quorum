(ns kotoba.lang.witness-quorum.quorum-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.lang.witness-quorum.quorum :as quorum]
            [kotoba.lang.witness-quorum.selector :as selector])
  (:import [java.util.concurrent LinkedBlockingQueue TimeUnit]))

(defn- witnesses [n]
  (vec (for [i (range n)] (selector/fleet-cell (str "node-" i) "CellA"))))

(defn- attest [cell verdict attested-at]
  {:cell-node (:node cell) :cell-id (:cell-id cell) :verdict verdict :attested-at attested-at})

(deftest quorum-state-accept-test
  (let [w (witnesses 5)
        atts [(attest (w 0) :accept "t1") (attest (w 1) :accept "t2") (attest (w 2) :accept "t3")]]
    (testing "reaches :witnessed once 3 accepts land (default threshold)"
      (is (= :witnessed (:kind (quorum/quorum-state w atts)))))))

(deftest quorum-state-reject-test
  (let [w (witnesses 5)
        atts [(attest (w 0) :reject "t1") (attest (w 1) :reject "t2") (attest (w 2) :reject "t3")]]
    (is (= :rejected (:kind (quorum/quorum-state w atts))))))

(deftest quorum-state-pending-test
  (let [w (witnesses 5)
        atts [(attest (w 0) :accept "t1")]]
    (testing "not enough attestations yet, and witnesses haven't all responded"
      (let [state (quorum/quorum-state w atts)]
        (is (= :pending (:kind state)))
        (is (= 4 (:remaining state)))))))

(deftest quorum-state-escalate-council-test
  (let [w (witnesses 5)
        ;; all 5 respond, but no verdict reaches the threshold of 3 (2 accept / 2 reject / 1 escalate)
        atts [(attest (w 0) :accept "t1") (attest (w 1) :accept "t2")
              (attest (w 2) :reject "t3") (attest (w 3) :reject "t4")
              (attest (w 4) :escalate "t5")]]
    (is (= {:kind :escalated :reason :no-threshold}
           (select-keys (quorum/quorum-state w atts) [:kind :reason])))))

(deftest quorum-state-escalate-policy-reject-test
  (testing "escalation-policy :reject falls back to :rejected on a genuine non-majority split (no escalate votes)"
    (let [w (witnesses 4)
          atts [(attest (w 0) :accept "t1") (attest (w 1) :accept "t2")
                (attest (w 2) :reject "t3") (attest (w 3) :reject "t4")]
          state (quorum/quorum-state w atts {:quorum-size 4 :quorum-threshold 3 :escalation-policy :reject})]
      (is (= :rejected (:kind state)))))

  (testing "any :escalate vote forces escalation regardless of :escalation-policy"
    (let [w (witnesses 3)
          atts [(attest (w 0) :accept "t1") (attest (w 1) :reject "t2") (attest (w 2) :escalate "t3")]
          state (quorum/quorum-state w atts {:quorum-size 3 :quorum-threshold 2 :escalation-policy :reject})]
      (is (= :escalated (:kind state))))))

(deftest quorum-state-dedup-latest-wins-test
  (let [w (witnesses 5)
        atts [(attest (w 0) :reject "t1") (attest (w 0) :accept "t2") ; same cell, later timestamp flips its verdict
              (attest (w 1) :accept "t1") (attest (w 2) :accept "t1")]]
    (is (= :witnessed (:kind (quorum/quorum-state w atts))))))

(deftest quorum-state-ignores-non-witness-attestations-test
  (let [w (witnesses 5)
        impostor (selector/fleet-cell "not-a-witness" "CellA")
        atts [(attest (w 0) :accept "t1") (attest (w 1) :accept "t2") (attest impostor :accept "t3")]]
    (is (= :pending (:kind (quorum/quorum-state w atts))))))

(deftest quorum-state-validates-inputs-test
  (testing "throws when threshold exceeds size"
    (is (thrown? clojure.lang.ExceptionInfo
                 (quorum/quorum-state (witnesses 3) [] {:quorum-size 3 :quorum-threshold 4}))))
  (testing "throws when witness count doesn't match quorum-size"
    (is (thrown? clojure.lang.ExceptionInfo
                 (quorum/quorum-state (witnesses 3) [] {:quorum-size 5})))))

;; --- collect-quorum, against a real LinkedBlockingQueue-backed poll-fn ---

(defn- queue-poll-fn [^LinkedBlockingQueue q]
  (fn [remaining-ms]
    (let [item (.poll q (long (max 0 remaining-ms)) TimeUnit/MILLISECONDS)]
      (if item {:status :value :value item} {:status :timeout}))))

(deftest collect-quorum-reaches-witnessed-test
  (let [w (witnesses 5)
        q (LinkedBlockingQueue.)]
    (doseq [i (range 3)] (.put q (attest (w i) :accept (str "t" i))))
    (let [state (quorum/collect-quorum w (queue-poll-fn q) {:quorum-size 5 :quorum-threshold 3 :timeout-ms 2000})]
      (is (= :witnessed (:kind state))))))

(deftest collect-quorum-times-out-pending-test
  (let [w (witnesses 5)
        q (LinkedBlockingQueue.)]
    (.put q (attest (w 0) :accept "t0"))
    (let [state (quorum/collect-quorum w (queue-poll-fn q) {:quorum-size 5 :quorum-threshold 3 :timeout-ms 200})]
      (is (= :pending (:kind state))))))
