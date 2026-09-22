# Changelog

## v0.1.0 — 2026-09-22

First release.

- `XMSS.verify(digest, sig, pk, treeHeight)`: on-chain verification of XMSS-SHA2_h_256 signatures (RFC 8391; n = 32, w = 16, h ≤ 20), stateless, using only the SHA-256 precompile. About 712k gas at h = 10 and 745k at h = 20. Binds the tree height as RFC 8391's public-key OID does; this is the recommended form. The three-argument `verify` takes the height from the signature instead (see PROOF.md).
- Formal verification with Halmos: each building block of the verifier is proven equal to the corresponding RFC 8391 algorithm for all inputs, plus the input checks, the height binding, the statelessness of the shared hash buffer, and the full composition at h = 2. The executable RFC 8391 specification it is proven against is checked against signatures from an independent Python implementation, which are in turn accepted by the RFC authors' C implementation. See [PROOF.md](PROOF.md) for what is proven, what is assumed, and the planted-bug and vacuity experiments.
- CI runs the tests, the cross-check against the C reference, and the proof on every push, and rejects a proof run that is truncated, near-vacuous, or carries solver warnings.
- Tests: vectors at h = 4, 10 and 20, tamper and fuzz tests, gas benchmarks.
- Not audited. Callers must enforce one-time use of each leaf index and pass the key's registered height (see README).
