## Fully Private Auctions in a Constant Number of Rounds

This workspace contains an implementation of the bidder–resolved uniform-price
auction protocol proposed by Felix Brandt in the **“Fully Private Auctions in a
Constant Number of Rounds”** paper (FC 2003, revised Feb. 2004 – see
`fc2003.pdf`). The protocol allows a group of bidders to run a second-price
(`M + 1`-st price) auction end-to-end without auctioneers or other trusted
third-parties while keeping every losing bid private.

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
- `pkg-config`/`openssl` as needed by `k256` (on Linux),
- `pdftotext` only if you plan to regenerate excerpts from `fc2003.pdf`.

Typical developer loop:

```bash
cargo fmt             # optional, ensures style
cargo clippy --all    # optional lint pass
cargo test            # runs elgamal and end-to-end Brandt flow tests
```

The `brandt::tests::linear_bidding_flow_selects_highest_bidder` unit test is a
useful sanity-check: it synthesizes multiple bidders, encrypts bids, verifies all
DLEQ/OR-DLEQ proofs, derives γ/Φ matrices, and checks a single winner emerges.

## Protocol walkthrough (code vs. paper)

| Paper reference            | Code hook                          | Notes |
|---------------------------|------------------------------------|-------|
| Section 4 (bidder-resolved auctions) | `brandt::make_onehot_bid` | Builds one-hot encrypted bid vectors \(b_i\) using group-wide ElGamal PK. |
| Section 5 (protocol description) | `brandt::BidVector::compute_bidder_share` | Reproduces the linear algebra on encrypted vectors ((2L−I), down shift, masking) using group operations. |
| Section 5.1 (ElGamal instantiation) | `elgamal.rs` & `proof.rs` | Implements the homomorphic encryption, Fiat–Shamir challenges, and ZK proof machinery. |
| Section 5.2 (ties) | TODO                                    | Tie-breaking logic from the paper is not yet wired into the crate. |

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
