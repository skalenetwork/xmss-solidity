# Formal verification of the XMSS verifier

`src/XMSS.sol` is proven, by symbolic execution, to compute what the verification algorithms of [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391) compute, for the XMSS-SHA2_h_256 parameter sets (n = 32, w = 16, len = 67; h ≤ 20).

## What is proven

[`test/proof/RFC8391.sol`](test/proof/RFC8391.sol) is an executable specification: the RFC's verification algorithms transcribed line by line, citing sections and algorithm numbers, written for fidelity rather than gas. [`test/proof/XMSSEquivalence.t.sol`](test/proof/XMSSEquivalence.t.sol) proves the production code equal to it with [Halmos](https://github.com/a16z/halmos). Every argument of a `check_*` function is symbolic, so a pass means the equality holds for **all** inputs.

| Lemma | Production (`src/XMSS.sol`) | RFC 8391 | Inputs |
|---|---|---|---|
| 1 | `chain` | Algorithm 2 (chain) | every X, SEED, OTS and chain address, and every start/steps with start + steps ≤ 15 |
| 2 | `randHash` with `adrs` | Algorithm 7 (RAND_HASH), §2.5 addresses | every input, L-tree and hash-tree addresses |
| 3 | `wotsChecksum`, `wotsDigit` | message encoding in Algorithm 6 (base_w of M' and of the checksum) | every M' |
| 4 | `ltree` | Algorithm 8 (ltree) | every 67 nodes, SEED, L-tree address |
| 5 | `climbStep` | one iteration of Algorithm 13's loop | every node, sibling, SEED, idx, and level k < 20 |
| 6 | (spec only) | Algorithm 13's tree-index update keeps floor(idx / 2^k) | every idx, k < 20 |
| 7 | `hMsg` | H_msg, §4.1.9 and §5.1 | every r, root, idx, M |
| 8 | `verify`'s input checks | domain of the parameter sets | rejects zero root or SEED, h = 0 or h > 20, idx ≥ 2^h |

**Composition.** `rootFromSig` is `wotsPkFromSig` (`chain` over the 67 digits from `wotsDigit`), then `ltree`, then `climbStep` for k = 0 … h−1, and `verify` compares its result with the root after `hMsg`. Algorithm 13 and Algorithm 14 have the same structure, so Lemmas 1–7 give the equality for every h by induction over the loop, with Lemma 6 as the loop invariant. This composition argument is checked by hand and, for all signatures, auth paths, SEEDs and indices at h = 2, symbolically (`check_rootFromSig_h2`). It is not machine-checked for general h.

## Assumptions and trust base

- **SHA-256 is modelled as an uninterpreted function.** The proofs hold for any hash function in that position, so they say nothing about SHA-256 itself; the security of XMSS rests on the published security proofs for XMSS and on SHA-256.
- **The specification is a human transcription of the RFC.** It is checked in three ways. It follows the RFC pseudocode literally. It accepts every signature produced by the RFC's reference implementation at h = 4, 10 and 20 and rejects each one for a different message (`test_spec_referenceVectors_*`). And every verified RFC 8391 erratum (as of 2026-09) was reviewed against it; none changes what verification computes:
  - 5572, 5573, 8382, 8383 and 8396 correct argument orders and a key-generation return value;
  - 7412 replaces `bits += 8` with `bits = 8` in base_w, identical since `bits` is 0 there;
  - 6821 corrects the documented checksum bound (the code relies on the correct bound, ≤ 960);
  - 6024 restates security levels.
- **Tooling.** Halmos 0.3.3 with Z3, over EVM bytecode compiled with this repository's settings (solc 0.8.37, via-IR, 200 optimizer runs). The proven bytecode is the test contract's compilation of the library; a contract that uses the library compiles it into its own bytecode, with the same source but in a different optimisation context. Halmos 0.3.3 declares the SHA-256 model with the wrong input width, `BitVecSorts[arg_size]` instead of `BitVecSorts[arg_size * 8]` in `sevm.py`, and needs that one-line fix to run these checks.
- **Not covered:** key generation and signing (only verification is specified and proven), gas behaviour, and any contract that uses the library.

## Checking that the proofs have teeth

Each check was also run against deliberately broken copies of `src/XMSS.sol`: swapped bitmasks in `randHash`, a wrong key/mask word in `chain`, an off-by-one hash address, a missing L-tree height increment, a dropped odd L-tree node, a wrong domain byte in F, and misplaced address words. Halmos returned a counterexample for every one.

## Running

```sh
halmos --match-contract XMSSEquivalence --loop 70 --solver-timeout-assertion 0
forge test --match-contract XMSSEquivalence   # the specification against the reference vectors
```
