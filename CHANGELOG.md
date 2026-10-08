# Changelog

## v1.1.0 — 2026-10-08

Adds XMSS^MT verification, makes the library product-neutral, and gives the Safe-based XMSS key registry, pre-approval engine and EIP drafts that FermionWallet built on this library a home in `reference/`, outside the library. `XMSS.verify`, its API, its proofs and its gas cost are unchanged; `src/XMSS.sol` differs from v1.0.0 in comments only.

- **Added** `src/XMSSMT.sol`: XMSS^MT verification (RFC 8391 §4.2, Algorithm 16) for a caller-bound total height h ≤ 60 and layer count d, in struct form (`verify`) and RFC 8391's byte encoding (`verifyEncoded`), with `validParams` and `MAX_TOTAL_HEIGHT`. Gas: about 1.85M at (20, 2), 3.34M at (20, 4), 6.99M at (40, 8) and 10.37M at (60, 12). **XMSS^MT is as stateful as XMSS: callers must record every `idx` they accept, per key, and refuse it again.**
- **Added** the XMSS^MT proof: `test/proof/RFC8391MT.sol` (the RFC's XMSS^MT additions, transcribed) and `test/proof/XMSSMTEquivalence.t.sol`, nine Halmos lemmas run in CI and guarded by `scripts/check_proof_run.py` (now told which proof file and path floors to use) with `scripts/proof-paths-mt.json`; written up in `test/proof/XMSSMT.md`.
- **Added** XMSS^MT vectors at (h, d) = (4, 2), (20, 2), (20, 4), (40, 8) and (60, 12) from a new independent Python implementation, `py/xmssmt_ref.py`. `scripts/crosscheck_reference.sh` now also checks the four standardized sets against the RFC authors' C implementation, which accepts every signature and rejects each with a tampered message.
- **Changed** the NatSpec, `PROOF.md`, the README, the project page and `py/sign_digest.py` to describe the library on its own terms rather than as FermionWallet's component. The NatSpec now states the caller's obligation directly: record each signature's `leafIdx` as spent. The `fermionwallet/...` labels in the Python key derivation stay, so the committed vectors are unchanged.
- **Changed** the project page: verifying ML-DSA costs millions of gas, not tens of millions. It now gives the measured comparison (about 0.7M for XMSS, about 2.7M for ML-DSA-44 with precomputation) and links [mldsa-solidity](https://github.com/skalenetwork/mldsa-solidity).
- **Added** `reference/`: application code that is **not part of the library**, moved here from [FermionWallet](https://github.com/skalenetwork/fermionwallet), which replaced XMSS with hybrid ECDSA + ML-DSA in its v2. It contains `QuantumKeyRegistry.sol` and `PreApprovalEngine.sol` (abstract), `XmssVerifier.sol` (the deployable `IXmssVerifier` contract) and its tests, the specifications in `reference/docs/`, the registry's Halmos equivalence proof in `reference/test/registry-proof/`, the XMSS verification, hash-based key registry and hybrid pre-approval ERC drafts (CC0) with `check_eips.py`, and `check_requirements.py` and `describe_spec.py`. The contract code is as in FermionWallet main at `b03aa8f`, relicensed from LGPL-3.0-only to MIT by its author; only imports and comments changed.
- **Dependencies**: none for the library. `reference/` needs OpenZeppelin Contracts at `acd4ff74de833399287ed6b31b4debf6b2b35527` and the Safe smart account at `dc437e8fba8b4805d76bcbd1c668c9fd3d1e83be`. They are deliberately not git submodules: `reference/scripts/setup-deps.sh` fetches them into `reference/lib/` (gitignored), so `forge install skalenetwork/xmss-solidity` and a recursive clone still fetch only forge-std. A separate `reference` Foundry profile builds `reference/` (`FOUNDRY_PROFILE=reference forge test`); the default profile never compiles it.
- **CI**: the test job also fetches the reference dependencies and runs the reference tests, `check_requirements.py`, `describe_spec.py --check`, `check_eips.py`, and two greps on the registry (it calls the four-argument `XMSS.verify` with the registered tree height; nothing overrides `_verifyAndConsumeXmss`). The prove job also proves `src/XMSSMT.sol`.

### Known issues

- **EIP-7702 delegation of the administrator (`reference/` only).** `QuantumKeyRegistry` checks the administrator's attestation, and `PreApprovalEngine` the classical half of every pre-approval, with OpenZeppelin's `SignatureChecker.isValidSignatureNow`, which chooses ECDSA or ERC-1271 from `quantumAdmin.code` at call time. If the administrator's EOA is delegated under EIP-7702 after registration, every later check silently becomes an ERC-1271 call to the delegate, which either refuses the device's genuine signatures or accepts whatever it chooses. FermionWallet fixed the same issue in its wallet contract as FWL-017a by fixing the branch at registration; the registry does not. See "Open issues" in `reference/docs/quantum-key-registry.md`.
- **Coverage stayed with the Guard (`reference/` only).** Most concrete tests of the registry and engine exercise them through FermionWallet's `FermionGuard` and stayed there. Here the registry is covered by the Halmos lemmas in `reference/test/registry-proof/` (run offline, not in CI) and the engine by none: `check_requirements.py` reports 15 of 36 `[QKR]` and 0 of 41 `[ENG]` requirements discharged.
- Not audited: neither the library nor `reference/`.

## v1.0.0 — 2026-09-30

First stable release. The verifier, the specification and the proofs are byte-for-byte those of v0.1.0; this release fixes the public API.

- **Stable API.** `XMSS.verify` (both forms), `XMSS.PublicKey`, `XMSS.Signature` and the constants `LEN`, `LEN1`, `W_MINUS_1` and `MAX_HEIGHT` will not change incompatibly within 1.x. The `internal` helpers the proofs check remain implementation detail.
- No change to the verifier, the RFC 8391 specification, the Halmos proofs or the gas cost (712,531 at h = 10; 745,003 at h = 20).
- Still **not audited**, and callers must still consume each leaf index once and pass the key's registered tree height (see README and PROOF.md).

## v0.1.0 — 2026-09-22

First release.

- `XMSS.verify(digest, sig, pk, treeHeight)`: on-chain verification of XMSS-SHA2_h_256 signatures (RFC 8391; n = 32, w = 16, h ≤ 20), stateless, using only the SHA-256 precompile. About 712k gas at h = 10 and 745k at h = 20. Binds the tree height as RFC 8391's public-key OID does; this is the recommended form. The three-argument `verify` takes the height from the signature instead (see PROOF.md).
- Formal verification with Halmos: each building block of the verifier is proven equal to the corresponding RFC 8391 algorithm for all inputs, plus the input checks, the height binding, the statelessness of the shared hash buffer, and the full composition at h = 2. The executable RFC 8391 specification it is proven against is checked against signatures from an independent Python implementation, which are in turn accepted by the RFC authors' C implementation. See [PROOF.md](PROOF.md) for what is proven, what is assumed, and the planted-bug and vacuity experiments.
- CI runs the tests, the cross-check against the C reference, and the proof on every push, and rejects a proof run that is truncated, near-vacuous, or carries solver warnings.
- Tests: vectors at h = 4, 10 and 20, tamper and fuzz tests, gas benchmarks.
- Not audited. Callers must enforce one-time use of each leaf index and pass the key's registered height (see README).
