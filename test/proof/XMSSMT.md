# Formal verification of the XMSS^MT verifier

`src/XMSSMT.sol` is proven, by symbolic execution, to compute what RFC 8391's XMSS^MT
verification (§4.2, Algorithm 16) computes, for the XMSSMT-SHA2_h/d_256 parameter sets
(n = 32, w = 16, len = 67; h ≤ 60, h/d ≤ 20). It builds on the XMSS proof in
[`PROOF.md`](../../PROOF.md): XMSS^MT reuses XMSS's keyed hashes, WOTS+ message encoding
and address packing unchanged, so those parts are proven once, there.

## What XMSS^MT adds, and what is proven about it

XMSS^MT is d XMSS trees stacked in layers. Layer 0's tree signs the message; each layer
above signs the root of the tree below; the top tree's root is the public key. Verification
differs from XMSS in three places, and each is proven against
[`RFC8391MT.sol`](RFC8391MT.sol), the RFC's XMSS^MT additions transcribed line by line, in
[`XMSSMTEquivalence.t.sol`](XMSSMTEquivalence.t.sol):

1. **Every hash address carries a layer and a 64-bit tree address** (§2.5 words 0–2), which
   XMSS always leaves zero. Production builds them as one `prefix` OR-ed into XMSS's address.
2. **The index walk.** Algorithm 16 splits idx_sig into a leaf and a tree address at each
   layer: the low h/d bits, then the rest.
3. **H_msg takes the full index** (up to 60 bits) rather than a 32-bit one.

| Lemma | Production (`src/XMSSMT.sol`) | RFC 8391 | Inputs |
|---|---|---|---|
| MT1 | `chain` with a prefix | Algorithm 2, in any tree | every X, SEED, layer, 64-bit tree address, OTS and chain address, start + steps ≤ 15 |
| MT2 | `XMSS.randHash` on a prefixed address | Algorithm 7, in any tree | every input, L-tree and hash-tree addresses |
| MT3 | `ltree` with a prefix | Algorithm 8, in any tree | every 67 nodes, SEED, layer, tree address, L-tree address |
| MT4 | `climbStep` with a prefix | one iteration of Algorithm 13's loop, in any tree | every node, sibling, SEED, layer, tree address, idx, level k < 20 |
| MT5 | `hMsg` | H_msg of Algorithm 16 (§4.2.4) | every r, root, 64-bit idx, M |
| MT6 | `splitIndex` across layers | Algorithm 16's idx_leaf / idx_tree updates | every idx < 2^h, every d ≤ 12 and h/d ≤ 20 with h ≤ 60; and the top tree is tree 0 |
| — | `prefix` with `XMSS.adrs` | the §2.5 byte layout | every layer, tree address, type and words 4–7 |
| MT7 | `verify`'s input checks | the domain of the parameter sets | false for every input with a zero root or SEED, invalid (h, d), the wrong layer count, an auth path not h/d long, or idx ≥ 2^h (signatures of up to 3 layers of up to 3 nodes) |
| comp. | `rootFromSig` | Algorithm 13 on the caller's ADRS | every WOTS+ signature, auth path, SEED, layer, tree address and leaf at h/d = 2, one fixed M' |

**Composition.** `verify` hashes the message with `hMsg`, then for each layer j computes
`rootFromSig` of the previous node in the tree at (j, idx_tree), and compares the last root
with the key. Algorithm 16 has the same structure. MT5 equates the hash, MT6 equates the
(leaf, tree address) handed to each layer, and the per-layer computation is XMSS's
Algorithm 13 in that tree (MT1–MT4, the prefix layout, and XMSS's Lemmas 3 and 6). The
per-layer composition is checked symbolically at h/d = 2 in every tree; the composition
across layers is a loop of identical steps, argued by induction and not machine-checked for
general d, as for XMSS's composition over k.

## Checked against code this project did not write

- The specification accepts every signature from an independent Python implementation
  ([`py/xmssmt_ref.py`](../../py/xmssmt_ref.py)) at (h, d) = (4, 2), (20, 2), (20, 4),
  (40, 8) and (60, 12), and rejects each for another message or another layer count
  (`test_spec_referenceVectors_*`).
- The RFC authors' C implementation (github.com/XMSS/xmss-reference, `xmssmt_open`) accepts
  every signature of the four RFC parameter sets among them and rejects each with a tampered
  message (`scripts/crosscheck_reference.sh`, 32 XMSS^MT checks besides XMSS's 16). The
  vectors include idx = 2^60 − 1, so every byte of the tree address is exercised.

## Run it

```
halmos --match-contract XMSSMTEquivalence --loop 70 --solver-timeout-assertion 0 | tee halmos-mt.log
python3 scripts/check_proof_run.py 70 halmos-mt.log test/proof/XMSSMTEquivalence.t.sol scripts/proof-paths-mt.json
```

The guard rejects a run that is truncated, near-vacuous (fewer paths than recorded in
`scripts/proof-paths-mt.json`) or carries solver warnings. With halmos 0.3.3 (and the SHA-256
model fix CI applies) and solc 0.8.37 all nine checks pass in about 14 minutes, nearly all of
it the composition check.

## Assumptions

As for XMSS: SHA-256 is an uninterpreted function, so the proofs say nothing about SHA-256
itself; the specification is a human transcription, checked as above. XMSS^MT, like XMSS, is
stateful: the library does not and cannot stop an index being used twice. The caller must
record every accepted idx and refuse it again. The proofs are about the bytecode solc 0.8.37
produces with the settings in `foundry.toml`.
