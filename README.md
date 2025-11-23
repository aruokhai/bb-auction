## Fully Private Auctions in a Constant Number of Rounds

This workspace implements a bidder–resolved uniform-price auction (Brandt, FC
2003, see `fc2003.pdf`) and shows how it can drive Arkade’s per-batch fee
discovery (`FeeDiscovery.pdf`).

### What you can do with this repo

- Run **fully private M+1 auctions** where losers stay hidden and only the
  clearing price is revealed.
- **Model Arkade batch fees**: derive a clearing rate `ρ_t` for K-radix batch
  liquidity, paying all winners the `(M + 1)`-st bid while keeping bids private.
- **Verify proofs end-to-end**: OR-DLEQ/DLEQ PoKs, homomorphic ElGamal
  operations, γ/Φ masking, and distributed decryptions are all checked in tests.
- **Prototype networking**: gRPC channel scaffolding for bidders/sellers is
  present for wiring real transports.
- **Extend the protocol**: tie/rollover handling, “seller-only price revelation,”
  and efficiency tweaks are highlighted for further work.

### Highlights from FC2003

- **Threat model:** All bidders may collude; privacy holds unless everyone
  reveals their shares voluntarily.
- **Cryptography:** Homomorphic ElGamal encryption, distributed public key,
  OR-proofs of discrete logarithm equality (OR-DLEQ), and standard DLEQ proofs.
- **Protocol shape:** Three broadcast rounds in the Random Oracle Model
  (key publication, encrypted bid vectors, masked winner indicators).
- **Outcome privacy:** Only winners and the seller learn the clearing price.
  Losing bidders learn nothing about other bids aside from the fact they lost.
- **Applicability:** Works for Vickrey auctions (`M = 1`) and uniform-price
  auctions with any `M ≥ 1`. Bid values are discretized into `k` slots that can
  be scaled to arbitrary price ranges.

The `fc2003.pdf` included in the repository contains the full explanation,
security proofs, and optimization notes (e.g., handling ties and efficiency
variants).

### Arkade batch liquidity fee discovery (proposal)

`FeeDiscovery.pdf` sketches how this codebase underpins Arkade’s per-batch fee
rate auction:

- **Batch economics:** Each batch needs `M · k` liquidity units; `M` cheapest
  providers win and all are paid the `(M + 1)`-st bid (`ρ_t`), keeping bidders
  truthful and the operator neutral.
- **Privacy + verifiability:** Bids are encrypted one-hot vectors; MPC over
  homomorphic ElGamal with ZK proofs yields only `ρ_t` and the winning keys.
  Losing bids and ordering remain hidden, but correctness is publicly
  auditable from the transcript.
- **Threat model:** Up to `n − 1` bidders and the operator may collude; fairness
  is enforced via bidder-resolved computation plus proof-checked partial
  decryptions.
- **Tie/rollover handling:** Ties at the marginal rate are admitted as
  conditionally winning capacity; surplus liquidity rolls into future batches
  without leaking tie structure, preserving temporal independence across rounds.
- **Outcome:** Arkade publishes `ρ_t`, winners hold proofs binding them to lock
  liquidity for the batch, and only winners’ identities are revealed to the
  operator for coordination.

## Crate layout

```
auction-core/
  src/
    brandt.rs   – Protocol logic closely following FC2003 (bid vectors,
                   bidder shares, Φ-matrix derivation, winner check).
    elgamal.rs  – Thin wrapper over `k256` implementing the homomorphic
                   ElGamal primitives used throughout the protocol.
    proof.rs    – OR-DLEQ, DLEQ, and Schnorr-style PoK helpers.
    types.rs    – Serializable data structures exchanged between actors.
    bidder.rs, seller.rs, channel.rs – (Currently commented / WIP) async
                   scaffolding for networked bidders and the seller.
    serde.rs    – Helpers for compact SEC1 serialization of curve points.
```

The top-level `Cargo.toml` defines a workspace with the `auction-core` crate.

## Building & testing

Requirements:

- Rust toolchain (edition 2024 features are enabled),

Typical developer loop:

```bash
cargo fmt             # optional, ensures style
cargo clippy --all    # optional lint pass
cargo test            # runs elgamal and end-to-end Brandt flow tests
```

The `brandt::tests::linear_bidding_flow_selects_highest_bidder` unit test is a
useful sanity-check: it synthesizes multiple bidders, encrypts bids, verifies all
DLEQ/OR-DLEQ proofs, derives γ/Φ matrices, and checks a single winner emerges.


## Running your own experiments

1. Choose auction parameters (`AuctionParams`) – number of price slots `k`,
   min/max price, winner count `m`, and bidder count.
2. For each bidder:
   - Generate a `BidVector` with `make_onehot_bid`.
   - Collect all `EncBidVector`s into a `BTreeSet` (public bulletin board).
3. Each bidder calls `compute_bidder_share` to create blinded γ/δ columns
   together with DLEQ proofs; verification happens automatically.
4. Use `derive_bidder_gamma_matrix` and `derive_bidder_phi_matrix` to assemble
   the per-bidder views, then `is_winner` to detect the winners.

Because all proof verification occurs before using shared data, malicious bids
are rejected before they can influence γ/Φ computations—mirroring the robustness
arguments from the paper.

## Roadmap and open questions

- Implement the optional “seller-only price revelation” path.
- Add support for more efficient blinding matrices described at the end of
  Section 5.
- Encode tie handling (Section 5.2) and publish explicit tests.
- Provide networking/channel glue to drive the async bidder/seller skeletons.

Contributions and issue reports are welcome; please cite the FC2003 paper when
filing protocol-level questions so discussions can reference the same notation.

## Reference

Felix Brandt, *Fully Private Auctions in a Constant Number of Rounds*, Lecture
Notes in Computer Science 2742, Financial Cryptography 2003 (revised Feb.
2004). Included locally as `fc2003.pdf`.
