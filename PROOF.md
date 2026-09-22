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
| 7 | `hMsg` | H_msg in Algorithm 14 (§4.1.10), §5.1 | every r, root, idx, M |
| 10 | shared scratch buffer | (memory safety, not an RFC algorithm) | every primitive gives the same result on a buffer full of arbitrary bytes as on a zeroed one: no call reads what a previous call left |
| 8 | `verify`'s input checks | domain of the parameter sets | returns false for every input with zero root or SEED, h = 0 or h > 20, or idx ≥ 2^h |
| 9 | `verify(…, treeHeight)` | the key's parameter set fixes h (§4.1.7, §5.3) | returns false whenever the signature does not carry exactly `treeHeight` authentication nodes |

**Composition.** `rootFromSig` is `wotsPkFromSig` (`chain` over the 67 digits from `wotsDigit`), then `ltree`, then `climbStep` for k = 0 … h−1, and `verify` compares its result with the root after `hMsg`. Algorithm 13 and Algorithm 14 have the same structure, so Lemmas 1–7 give the equality for every h by induction over the loop, with Lemma 6 as the loop invariant. This composition argument is checked by hand and, for all signatures, auth paths, SEEDs and indices at h = 2 with one fixed M', symbolically (`check_rootFromSig_h2`; with a symbolic M' the solver did not finish within 40 minutes). It is not machine-checked for general h.

## Tree height and the public key

RFC 8391's public key is `OID || root || SEED` (§4.1.7). The OID names the parameter set and so fixes the tree height h (§5.3); a signature for that set carries exactly h authentication nodes (§4.1.8). `XMSS.PublicKey` holds only `root` and `SEED`, so the library offers two forms:

- **`verify(M, sig, pk, treeHeight)`**, recommended. The caller supplies the height it registered for the key, and a signature with a different number of authentication nodes is rejected (Lemma 9). With a matching height it computes exactly the specification's `XMSS_verify(h, …)`, which takes h from the parameter set as the RFC does.
- **`verify(M, sig, pk)`** takes h from `sig.authPath.length`, so whoever supplies the signature also chooses the height (1 to 20, including non-standard heights). It equals the specification's `XMSS_verify` with h set to the signature's own height. Use it only if you bind the height yourself; FermionWallet's key registry does, by comparing `authPath.length` with the height stored for the key.

Accepting a signature under a height other than the key's would need a collision in the tree root, so the practical risk of the three-argument form is low, but only the four-argument form matches the RFC's key model.

## Assumptions and trust base

- **SHA-256 is modelled as an uninterpreted function.** The proofs hold for any hash function in that position, so they say nothing about SHA-256 itself; the security of XMSS rests on the published security proofs for XMSS and on SHA-256.
- **The specification is a human transcription of the RFC.** It is checked in four ways. The test vectors it must accept are also accepted, and their tampered copies rejected, by the RFC authors' own C implementation (github.com/XMSS/xmss-reference; `scripts/crosscheck_reference.sh`, run in CI), which this project did not write. It follows the RFC pseudocode literally. It accepts every signature produced by an independent Python implementation of RFC 8391 (`py/xmss_ref.py`, written for this project; not the RFC authors' C reference implementation, against which it has not yet been cross-checked) at h = 4, 10 and 20, and rejects each one for a different message (`test_spec_referenceVectors_*`). And every verified RFC 8391 erratum (as of 2026-09) was reviewed against it; none changes what verification computes:
  - 5572, 5573, 8382, 8383 and 8396 correct argument orders and a key-generation return value;
  - 7412 replaces `bits += 8` with `bits = 8` in base_w, identical since `bits` is 0 there;
  - 6821 corrects the documented checksum bound (the code relies on the correct bound, ≤ 960);
  - 6024 restates security levels.
- **Tooling.** Halmos 0.3.3 with Z3, over EVM bytecode compiled with this repository's settings (solc 0.8.37, via-IR, 200 optimizer runs). The proven bytecode is the test contract's compilation of the library; a contract that uses the library compiles it into its own bytecode, with the same source but in a different optimisation context. Halmos 0.3.3 declares the SHA-256 model with the wrong input width, `BitVecSorts[arg_size]` instead of `BitVecSorts[arg_size * 8]` in `sevm.py`, and needs that one-line fix to run these checks.
- **Not covered:** key generation and signing (only verification is specified and proven), gas behaviour, and any contract that uses the library.

## Proof run

Halmos 0.3.3 (Z3), solc 0.8.37 via-IR, for release v0.1.0. All 11 checks pass; CI re-runs them on every push and rejects a run that is truncated, near-vacuous, or carries solver warnings (`scripts/check_proof_run.py`).

| Check | Paths | Time |
|---|---|---|
| `check_chain` | 51 | 2.2 s |
| `check_randHash` | 6 | < 0.1 s |
| `check_wotsDigits` | 316 | 5.0 s |
| `check_ltree` | 2 | 0.8 s |
| `check_climbStep` | 16 | 1.5 s |
| `check_treeIndexInvariant` | 7 | 3.9 s |
| `check_hMsg` | 2 | < 0.1 s |
| `check_verifyRejectsOutOfDomain` | 77 | 0.6 s |
| `check_rootFromSig_h2` | 14 | 526 s |

## Checking that the proofs have teeth

A proof of "production equals specification" is only as good as the specification, and a check with too strong a precondition can pass on no inputs at all. Three experiments guard against both.

**Bugs planted in production.** Each check was run against deliberately broken copies of `src/XMSS.sol`: swapped bitmasks in `randHash`, a wrong key/mask word in `chain`, an off-by-one hash address, a missing L-tree height increment, a dropped odd L-tree node, a wrong domain byte in F, and misplaced address words. Halmos returned a counterexample for every one.

**Bugs planted in the specification.** The same was done to `RFC8391.sol`, which the production-side experiment cannot cover: swapped bitmasks in RAND_HASH, a wrong hash address in chain, base_w reading nibbles in the wrong order, an unshifted checksum, a dropped odd L-tree node, H_msg without the index, wrong domain bytes for PRF and for F/H, and an inverted left/right decision in the tree climb. Every one produced a Halmos counterexample *and* failed the vector tests, so the specification is pinned from both sides. Two further mutations survived, and both are provably no-ops rather than blind spots: replacing `(t − 1) / 2` by `t / 2` in the right-child index update (t is odd on that branch, so the values are equal; this is exactly Lemma 6), and `setType` not zeroing the keyAndMask word (every consumer sets that word explicitly before each PRF call, so the stale value is never read).

**Vacuity.** With each lemma's assertion replaced by `assert(false)`, Halmos reports a failure on 20 (`check_chain`), 77 (`check_verifyRejectsOutOfDomain`) and 189 (`check_wotsDigits`) paths, so the `vm.assume` preconditions leave real inputs to explore. The path counts Halmos prints for every check (in CI and above) are the same evidence for the others.

## Running

```sh
halmos --match-contract XMSSEquivalence --loop 70 --solver-timeout-assertion 0
forge test --match-contract XMSSEquivalence   # the specification against the reference vectors
```
