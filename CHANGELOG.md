# Changelog

## v0.1.0 — 2026-09-22

First release.

- `XMSS.verify(digest, sig, pk, treeHeight)`: binds the tree height as RFC 8391's public-key OID does, and is the recommended form. The three-argument `verify` takes the height from the signature; see PROOF.md.

- `XMSS.verify`: on-chain verification of XMSS-SHA2_h_256 signatures (RFC 8391; n = 32, w = 16, h ≤ 20), stateless, SHA-256 precompile. About 712k gas at h = 10 and 745k at h = 20.
- Formal verification: Halmos proofs that each building block equals the RFC 8391 algorithm for all inputs, an executable RFC 8391 specification checked against signatures from an independent Python implementation of RFC 8391, and a symbolic check of the full composition at h = 2. See [PROOF.md](PROOF.md) for what is proven and assumed.
- Tests: reference vectors at h = 4, 10 and 20, tamper and fuzz tests, gas benchmarks.
- Not audited. Callers must enforce one-time use of each leaf index (see README).
