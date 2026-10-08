// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {XMSS} from "../../src/XMSS.sol";
import {XMSSMT} from "../../src/XMSSMT.sol";
import {RFC8391} from "./RFC8391.sol";
import {RFC8391MT} from "./RFC8391MT.sol";

/// @title Equivalence of src/XMSSMT.sol with RFC 8391 §4.2 (see XMSSMT.md in this folder)
/// @notice As in XMSSEquivalence.t.sol: `check_*` functions are symbolic proofs run by
///         Halmos, with SHA-256 an uninterpreted function, so a PASS holds for ALL
///         inputs; `test_*` functions are Foundry tests of the specification against
///         vectors from py/xmssmt_ref.py.
///
///         halmos --match-contract XMSSMTEquivalence --loop 70
///
///         What XMSS^MT adds to XMSS is the layer and tree address in words 0-2 of every
///         hash address, the index walk across layers, and a 60-bit index in H_msg. The
///         lemmas below cover exactly those, for every layer and every 64-bit tree
///         address; the parts reused unchanged from XMSS (prf, fHash, randHash's key and
///         mask clearing, the WOTS+ digits, the scratch buffer) are XMSSEquivalence's.
contract XMSSMTEquivalence is Test {
    function _scratch() internal pure returns (uint256 scratch) {
        bytes memory buf = new bytes(160);
        assembly ("memory-safe") {
            scratch := add(buf, 32)
        }
    }

    function _adrs(uint32 layer, uint64 tree, uint32 typ) internal pure returns (RFC8391.ADRS memory a) {
        RFC8391MT.setLayerAddress(a, layer);
        RFC8391MT.setTreeAddress(a, tree);
        RFC8391.setType(a, typ);
    }

    // ── Lemma MT1: chain with a layer/tree address == Algorithm 2 ──────────

    function check_mtChain(
        bytes32 X,
        bytes32 SEED,
        uint32 layer,
        uint64 tree,
        uint32 ots,
        uint32 chainAddr,
        uint8 start,
        uint8 steps
    ) public view {
        vm.assume(uint256(start) + steps <= 15);
        bytes32 impl = XMSSMT.chain(X, ots, chainAddr, start, steps, XMSSMT.prefix(layer, tree), SEED, _scratch());
        RFC8391.ADRS memory a = _adrs(layer, tree, 0);
        RFC8391.setOTSAddress(a, ots);
        RFC8391.setChainAddress(a, chainAddr);
        assertEq(impl, RFC8391.chain(X, start, steps, SEED, a));
    }

    // ── Lemma MT2: randHash on a prefixed address == Algorithm 7 ───────────

    function check_mtRandHash(
        bytes32 L,
        bytes32 R,
        bytes32 SEED,
        uint32 layer,
        uint64 tree,
        uint32 w4,
        uint32 w5,
        uint32 w6,
        bool ltreeType
    ) public view {
        uint32 typ = ltreeType ? 1 : 2;
        bytes32 adr = bytes32(XMSSMT.prefix(layer, tree) | uint256(XMSS.adrs(typ, w4, w5, w6, 0)));
        bytes32 impl = XMSS.randHash(L, R, SEED, adr, _scratch());
        RFC8391.ADRS memory a = _adrs(layer, tree, typ);
        a.word[4] = w4;
        a.word[5] = w5;
        a.word[6] = w6;
        assertEq(impl, RFC8391.RAND_HASH(L, R, SEED, a));
    }

    // ── Lemma MT3: ltree with a layer/tree address == Algorithm 8 ──────────

    function check_mtLtree(bytes32[67] memory nodes, bytes32 SEED, uint32 layer, uint64 tree, uint32 ltreeAddr)
        public
        view
    {
        bytes32[67] memory copy;
        for (uint256 i = 0; i < 67; i++) {
            copy[i] = nodes[i];
        }
        bytes32 impl = XMSSMT.ltree(nodes, ltreeAddr, XMSSMT.prefix(layer, tree), SEED, _scratch());
        RFC8391.ADRS memory a = _adrs(layer, tree, 1);
        RFC8391.setLTreeAddress(a, ltreeAddr);
        assertEq(impl, RFC8391.ltree(copy, SEED, a));
    }

    // ── Lemma MT4: climbStep with a layer/tree address == Algorithm 13's step ──

    /// With XMSSEquivalence's Lemma 6 (the tree index on entry to step k is
    /// floor(idx / 2^k)), production's k-th climb step equals the RFC's, in every tree.
    function check_mtClimbStep(bytes32 node, bytes32 authK, bytes32 SEED, uint32 layer, uint64 tree, uint32 idx, uint8 k)
        public
        view
    {
        vm.assume(k < 20);
        bytes32 impl = XMSSMT.climbStep(node, authK, idx, k, XMSSMT.prefix(layer, tree), SEED, _scratch());
        RFC8391.ADRS memory a = _adrs(layer, tree, 2);
        RFC8391.setTreeIndex(a, uint32(uint256(idx) >> k));
        assertEq(impl, RFC8391.rootStep(node, authK, idx, k, SEED, a));
    }

    // ── Lemma MT5: hMsg == H_msg with the full index (§4.2.4) ──────────────

    function check_mtHMsg(bytes32 r, bytes32 root, uint64 idx, bytes32 M) public pure {
        assertEq(XMSSMT.hMsg(r, root, idx, M), RFC8391MT.H_msg(r, root, idx, M));
    }

    // ── Lemma MT6: verify's index walk == Algorithm 16's ───────────────────

    /// For every index and every valid (h, d) — here every d up to 12 and every
    /// h/d up to 20 with h <= 60 — the (leaf, tree address) pair production hands to
    /// layer j is the RFC's: leaf = the h/d least significant bits of the current
    /// index, tree address = its remaining most significant bits.
    function check_mtIndexWalk(uint64 idx, uint8 hp, uint8 d) public pure {
        vm.assume(d >= 2 && d <= 12 && hp >= 1 && hp <= 20 && uint256(hp) * d <= 60);
        uint256 h = uint256(hp) * d;
        vm.assume(uint256(idx) < (uint256(1) << h));
        uint64 implTree = idx;
        uint256 specTree = idx;
        uint256 bits = h; // bits in the RFC's current idx_tree
        for (uint256 j = 0; j < 12; j++) {
            if (j < d) {
                (uint32 implLeaf, uint64 implNext) = XMSSMT.splitIndex(implTree, hp);
                uint256 specLeaf = RFC8391MT.lsb(specTree, hp);
                specTree = RFC8391MT.msb(specTree, bits, bits - hp);
                bits -= hp;
                implTree = implNext;
                assert(uint256(implLeaf) == specLeaf);
                assert(uint256(implTree) == specTree);
            }
        }
        assert(implTree == 0); // the top layer's tree is tree 0, as keygen builds it
    }

    /// The layer prefix lays out words 0-2 exactly as §2.5 does, so OR-ing it into an
    /// XMSS address (whose words 0-2 are zero) gives the RFC's full address.
    function check_mtPrefixLayout(uint32 layer, uint64 tree, uint32 typ, uint32 w4, uint32 w5, uint32 w6, uint32 km)
        public
        pure
    {
        RFC8391.ADRS memory a = _adrs(layer, tree, typ);
        a.word[4] = w4;
        a.word[5] = w5;
        a.word[6] = w6;
        a.word[7] = km;
        assertEq(bytes32(XMSSMT.prefix(layer, tree) | uint256(XMSS.adrs(typ, w4, w5, w6, km))), RFC8391.toBytes(a));
    }

    // ── Lemma MT7: verify's input checks ───────────────────────────────────

    /// Production rejects, before hashing anything, every input outside the supported
    /// domain: zero root or SEED; (h, d) with fewer than two layers, layers not dividing
    /// h, trees above 20 or h above 60; a signature whose layer count is not d or whose
    /// auth paths are not h/d long; idx >= 2^h. Halmos needs concrete array lengths, so
    /// the signature shape ranges over up to 3 layers of up to 3 nodes.
    function check_mtVerifyRejectsOutOfDomain(
        bytes32 M,
        uint64 idx,
        bytes32 r,
        bytes32 root,
        bytes32 seed,
        uint8 h,
        uint8 d,
        uint8 nLayers,
        uint8 authLen
    ) public view {
        vm.assume(nLayers <= 3 && authLen <= 3);
        bool inDomain = root != 0 && seed != 0 && XMSSMT.validParams(h, d) && nLayers == d
            && uint256(authLen) == uint256(h) / d && uint256(idx) < (uint256(1) << h);
        vm.assume(!inDomain);
        for (uint256 nl = 0; nl <= 3; nl++) {
            for (uint256 al = 0; al <= 3; al++) {
                if (nl == nLayers && al == authLen) {
                    XMSSMT.Signature memory sig;
                    sig.idx = idx;
                    sig.r = r;
                    sig.layers = new XMSSMT.Layer[](nl);
                    for (uint256 j = 0; j < nl; j++) {
                        sig.layers[j].authPath = new bytes32[](al);
                    }
                    assertFalse(XMSSMT.verify(M, sig, XMSS.PublicKey(root, seed), h, d));
                }
            }
        }
    }

    // ── Composition, checked symbolically at small height ──────────────────

    /// One layer of the hypertree: rootFromSig composes wotsPkFromSig, ltree and
    /// climbStep as Algorithm 13 does, in EVERY tree (symbolic layer and 64-bit tree
    /// address), for all WOTS+ signatures, auth paths, SEEDs and leaves of a height-2
    /// tree, at a fixed M' (as XMSSEquivalence's check_rootFromSig_h2: a symbolic M'
    /// does not finish; Lemma MT1 and XMSSEquivalence's Lemma 3 cover every chain length).
    function check_mtRootFromSig_h2(
        bytes32[67] memory wotsSig,
        bytes32 a0,
        bytes32 a1,
        bytes32 SEED,
        uint32 layer,
        uint64 tree,
        uint8 idx
    ) public view {
        vm.assume(idx < 4);
        bytes32 mPrime = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0;
        XMSSMT.Layer memory l;
        l.authPath = new bytes32[](2);
        l.authPath[0] = a0;
        l.authPath[1] = a1;
        bytes32[67] memory copy;
        for (uint256 i = 0; i < 67; i++) {
            l.wotsSig[i] = wotsSig[i];
            copy[i] = wotsSig[i];
        }
        bytes32 impl = XMSSMT.rootFromSig(mPrime, l, idx, XMSSMT.prefix(layer, tree), SEED, _scratch());
        RFC8391.ADRS memory a;
        RFC8391MT.setLayerAddress(a, layer);
        RFC8391MT.setTreeAddress(a, tree);
        assertEq(impl, RFC8391MT.XMSS_rootFromSig(idx, copy, l.authPath, mPrime, SEED, a));
    }

    // ── The specification against an independent Python implementation ────

    function _spec(string memory file, uint256 i)
        internal
        view
        returns (uint256 h, uint256 d, bytes32 M, uint256 idx, bytes32 r, RFC8391MT.Layer[] memory layers, bytes32 root, bytes32 seed)
    {
        string memory json = vm.readFile(string.concat("test/vectors/", file));
        h = vm.parseJsonUint(json, ".h");
        d = vm.parseJsonUint(json, ".d");
        root = vm.parseJsonBytes32(json, ".root");
        seed = vm.parseJsonBytes32(json, ".seed");
        string memory base = string.concat(".vectors[", vm.toString(i), "]");
        idx = vm.parseJsonUint(json, string.concat(base, ".idx"));
        r = vm.parseJsonBytes32(json, string.concat(base, ".r"));
        M = vm.parseJsonBytes32(json, string.concat(base, ".msg"));
        layers = new RFC8391MT.Layer[](d);
        for (uint256 j = 0; j < d; j++) {
            string memory lb = string.concat(base, ".layers[", vm.toString(j), "]");
            bytes32[] memory w = vm.parseJsonBytes32Array(json, string.concat(lb, ".wotsSig"));
            for (uint256 k = 0; k < 67; k++) layers[j].sig_ots[k] = w[k];
            layers[j].auth = vm.parseJsonBytes32Array(json, string.concat(lb, ".auth"));
        }
    }

    /// One run of the spec on reference vector i, in its own call frame (the spec
    /// allocates freely, and memory cost grows with everything a frame has allocated):
    /// mode 0 as signed, 1 with another message, 2 with twice the layer count.
    function specVerify(string memory file, uint256 i, uint256 mode) external view returns (bool) {
        (uint256 h, uint256 d, bytes32 M, uint256 idx, bytes32 r, RFC8391MT.Layer[] memory layers, bytes32 root, bytes32 seed)
        = _spec(file, i);
        if (mode == 1) M = bytes32(uint256(M) ^ 1);
        if (mode == 2) d *= 2;
        return RFC8391MT.XMSSMT_verify(h, d, M, idx, r, layers, root, seed);
    }

    /// The spec accepts every signature from py/xmssmt_ref.py and rejects it for any
    /// other message and any other layer count, so the transcription computes what
    /// RFC 8391 computes (and what the RFC authors' C implementation accepts).
    function _specAgainstReference(string memory file) internal view {
        for (uint256 i = 0; i < 4; i++) {
            assertTrue(this.specVerify(file, i, 0), "spec rejects a reference signature");
            assertFalse(this.specVerify(file, i, 1), "spec accepts a wrong message");
            assertFalse(this.specVerify(file, i, 2), "spec accepts another layer count");
        }
    }

    function test_spec_referenceVectors_h4_d2() public view {
        _specAgainstReference("xmssmt_h4_d2.json");
    }

    function test_spec_referenceVectors_h20_d2() public view {
        _specAgainstReference("xmssmt_h20_d2.json");
    }

    function test_spec_referenceVectors_h20_d4() public view {
        _specAgainstReference("xmssmt_h20_d4.json");
    }

    function test_spec_referenceVectors_h40_d8() public view {
        _specAgainstReference("xmssmt_h40_d8.json");
    }

    function test_spec_referenceVectors_h60_d12() public view {
        _specAgainstReference("xmssmt_h60_d12.json");
    }
}
