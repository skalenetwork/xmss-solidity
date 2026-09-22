# xmss-solidity

On-chain verification of **XMSS** post-quantum signatures ([RFC 8391](https://www.rfc-editor.org/rfc/rfc8391)), in Solidity, **formally verified against the RFC**.

- **Parameter sets:** XMSS-SHA2_h_256 (SHA-256, n = 32, w = 16, len = 67), single tree, h = 10, 16 or 20 (NIST SP 800-208). h = 4 is supported for testing.
- **Stateless and storage-free.** One `internal` library, `XMSS.verify`, using the SHA-256 precompile.
- **Gas:** about 712k at h = 10 and 745k at h = 20.
- **Formally verified:** proven by symbolic execution ([Halmos](https://github.com/a16z/halmos)) to compute what RFC 8391's verification algorithms compute, for all inputs. See [PROOF.md](PROOF.md) for what is proven, how, and what is assumed.

```solidity
import {XMSS} from "xmss-solidity/XMSS.sol";

bool ok = XMSS.verify(messageDigest, signature, XMSS.PublicKey(root, seed));
```

## XMSS is stateful: never verify without consuming the leaf

XMSS is a one-time-signature scheme under a Merkle tree. Each leaf index may sign **once**; a second signature with the same leaf leaks enough of the one-time key to forge. The library only checks that a signature is valid. A contract that uses it **must** record every `leafIdx` it accepts for a key and reject reuse. [FermionWallet](https://github.com/skalenetwork/fermionwallet) does this in its key registry.

## Install

```sh
forge install skalenetwork/xmss-solidity
```

Add the remapping `xmss-solidity/=lib/xmss-solidity/src/`.

## Layout

| Path | What |
|---|---|
| `src/XMSS.sol` | the verifier |
| `test/proof/RFC8391.sol` | executable specification: RFC 8391's verification algorithms, transcribed line by line |
| `test/proof/XMSSEquivalence.t.sol` | the Halmos proofs, and the specification checked against the reference vectors |
| `test/XMSS.t.sol`, `test/XMSSProperties.t.sol` | unit, gas and fuzz tests |
| `test/vectors/` | signatures from the Python reference implementation, h = 4, 10 and 20 |
| `py/xmss_ref.py` | independent Python reference implementation (key generation, signing, verification); regenerates the h = 4 and 10 vectors |
| `py/gen_h20.py` | regenerates the h = 20 vectors (about 10 minutes on all cores) |
| `py/sign_digest.py` | test helper: signs a digest with a deterministic test key, for Foundry FFI |

## Test and prove

```sh
forge test
halmos --match-contract XMSSEquivalence --loop 70 --solver-timeout-assertion 0
```

Halmos 0.3.3 needs a one-line fix to its SHA-256 model first; see [PROOF.md](PROOF.md#assumptions-and-trust-base) and the CI workflow.

## Licence

MIT.
