# Reference implementation: XMSS key registry and pre-approval engine

**This folder is application code, not part of the library.** It is a Safe-based XMSS key
registry and hybrid (ECDSA + XMSS) pre-approval engine, kept as the reference implementation
of the three ERC drafts in [`eips/`](eips/README.md). It moved here from
[FermionWallet](https://github.com/skalenetwork/fermionwallet), which used it in its
FermionGuard Safe guard until FermionWallet v2 replaced XMSS with hybrid ECDSA + ML-DSA.
It is **not audited** and has **no stable API**; `src/XMSS.sol` at the repository root does not
depend on anything here.

| Path | What |
|---|---|
| [`src/QuantumKeyRegistry.sol`](src/QuantumKeyRegistry.sol) | abstract: one device-held XMSS key per Safe; co-signed registration, rotation with an old-key possession proof, time-locked revocation, the used-leaf record keyed by root |
| [`src/PreApprovalEngine.sol`](src/PreApprovalEngine.sol) | abstract: time-bound approvals carrying an ECDSA and an XMSS signature over one EIP-712 digest, consumed at execution |
| [`src/XmssVerifier.sol`](src/XmssVerifier.sol) | a deployable, stateless `IXmssVerifier` contract around `XMSS.verify`, with ERC-165 |
| [`docs/`](docs/quantum-key-registry.md) | the registry and engine specifications, with `[QKR-nnn]` and `[ENG-nnn]` requirement IDs |
| [`test/registry-proof/`](test/registry-proof/README.md) | the registry's state machine as executable code, proven equivalent to the contract with Halmos |
| [`test/XmssVerifier.t.sol`](test/XmssVerifier.t.sol) | `XmssVerifier`'s tests |
| [`eips/`](eips/README.md) | the ERC drafts (CC0) and `check_eips.py` |
| `scripts/` | `setup-deps.sh` (fetches OpenZeppelin and Safe into `lib/`), `check_requirements.py` (requirement-ID traceability) and `describe_spec.py` (renders the registry proof's specification as `DESCRIPTION.md`) |

The two registry contracts are `abstract`: FermionWallet compiled them into its Safe guard,
which stayed in FermionWallet together with most of their concrete tests. They need
OpenZeppelin Contracts and the Safe smart account at the commits FermionWallet pinned. These are
not git submodules, so installing the library never fetches them:
[`scripts/setup-deps.sh`](scripts/setup-deps.sh) clones both into `reference/lib/` (gitignored),
and the `reference` profile in `foundry.toml` remaps them there.
Known issues are in the repository's [CHANGELOG](../CHANGELOG.md).

## Build, test, check

From the repository root. The `reference` Foundry profile compiles this folder; the default
profile, which builds and proves the library, never does.

```sh
reference/scripts/setup-deps.sh
FOUNDRY_PROFILE=reference forge test
FOUNDRY_PROFILE=reference halmos --forge-build-out out/reference --match-contract RegistryEquivalence --loop 32 --solver-timeout-assertion 0
python3 reference/scripts/check_requirements.py
python3 reference/scripts/describe_spec.py --check reference/test/registry-proof/DESCRIPTION.md
python3 reference/eips/check_eips.py
```

The Halmos run needs the same SHA-256 model fix as the library's proof (see the CI workflow).
CI runs everything above except Halmos.
