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

### Foundry (recommended)

```sh
forge install skalenetwork/xmss-solidity@v0.1.0
```

Add the remapping to `remappings.txt` (or `foundry.toml`):

```
xmss-solidity/=lib/xmss-solidity/src/
```

### Git submodule (without `forge install`)

```sh
git submodule add https://github.com/skalenetwork/xmss-solidity lib/xmss-solidity
cd lib/xmss-solidity && git checkout v0.1.0 && cd -
```

Then add the same remapping as above.

### Hardhat or other npm-based setups

```sh
npm install github:skalenetwork/xmss-solidity#v0.1.0
```

```solidity
import {XMSS} from "xmss-solidity/src/XMSS.sol";
```

### Compiler settings

The library needs Solidity ^0.8.24 and no other dependencies. The formal proof covers the bytecode produced with **solc 0.8.37, via-IR, 200 optimizer runs** (see `foundry.toml`). Other compiler versions or settings compile the same source, but not the exact bytecode that was proven, so use these settings if you rely on the proof.

## Use

```solidity
import {XMSS} from "xmss-solidity/XMSS.sol";

contract MyVerifier {
    mapping(bytes32 => mapping(uint32 => bool)) public leafUsed; // per key: one-time leaves

    function check(bytes32 digest, XMSS.Signature memory sig, bytes32 root, bytes32 seed) external {
        bytes32 key = keccak256(abi.encode(root, seed));
        require(!leafUsed[key][sig.leafIdx], "leaf already used");
        require(XMSS.verify(digest, sig, XMSS.PublicKey(root, seed)), "invalid XMSS signature");
        leafUsed[key][sig.leafIdx] = true; // XMSS is stateful: never accept a leaf twice
    }
}
```

`XMSS.Signature` is `{uint32 leafIdx; bytes32 r; bytes32[67] wotsSig; bytes32[] authPath}`; the tree height is the length of `authPath`. `py/xmss_ref.py` generates keys and signatures in this format for testing.

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
