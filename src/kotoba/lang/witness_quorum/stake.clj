(ns kotoba.lang.witness-quorum.stake
  "Internal staking-bond accounting for witness cells (ADR-2607110300 Phase
  4). NOT real money: no external custody, no chain settlement, no
  currency unit -- this is an in-memory/injectable ledger of bond UNITS a
  cell has 'posted' and can be 'slashed' from. Same honesty caveat as
  cloud-murakumo.ledger.witness/run-cid's non-cryptographic CID: real
  economic staking requires the Phase-3 chain gateway and ENGI
  cross-agent verification (blocked on ADR-2607022600 Wave 4), neither of
  which is wired here. This module is the accounting SHAPE Phase 4's real
  staking would use once those land -- exercised now with abstract unit
  amounts, not currency."
  )

(def empty-ledger {})

(defn post-bond
  "Add `amount` (>= 0) bond units to cell-key's balance."
  [ledger cell-key amount]
  (when (neg? amount) (throw (ex-info "stake: bond amount must be >= 0" {:amount amount})))
  (update ledger cell-key (fnil + 0) amount))

(defn balance [ledger cell-key] (get ledger cell-key 0))

(defn slash!
  "Reduce cell-key's bond by up to `amount` (>= 0). Never goes negative --
  an over-slash clamps to the current balance rather than overdrawing,
  since there is no real custody behind this ledger to go negative
  against. Returns `{:ledger ledger' :slashed n}` where `n` (<= amount) is
  the amount actually removed."
  [ledger cell-key amount]
  (when (neg? amount) (throw (ex-info "stake: slash amount must be >= 0" {:amount amount})))
  (let [current (balance ledger cell-key)
        removed (min current amount)]
    {:ledger (update ledger cell-key (fnil - 0) removed)
     :slashed removed}))
