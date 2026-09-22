// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {XMSS} from "../../src/XMSS.sol";
import {RFC8391} from "./RFC8391.sol";

/// @title Equivalence of src/XMSS.sol with RFC 8391 (see README.md in this folder)
/// @notice `check_*` functions are symbolic proofs run by Halmos: every argument is
///         symbolic, so a PASS means the assertion holds for ALL inputs, with
///         SHA-256 modelled as an uninterpreted function (the result does not depend
///         on any property of SHA-256). `test_*` functions are ordinary Foundry tests
///         of the specification against the RFC reference implementation's vectors.
///
///         halmos --match-contract XMSSEquivalence --loop 70
contract XMSSEquivalence is Test {
    function _scratch() internal pure returns (uint256 scratch) {
        bytes memory buf = new bytes(160);
        assembly ("memory-safe") {
            scratch := add(buf, 32)
        }
    }

    // ── Lemma 1: chain == Algorithm 2 ──────────────────────────────────────

    /// For every X, SEED, OTS address, chain address and every (start, steps) with
    /// start + steps <= w - 1 (the only calls XMSS makes): equal outputs.
    function check_chain(bytes32 X, bytes32 SEED, uint32 ots, uint32 chainAddr, uint8 start, uint8 steps)
        public
        view
    {
        vm.assume(uint256(start) + steps <= 15);
        bytes32 impl = XMSS.chain(X, ots, chainAddr, start, steps, SEED, _scratch());
        RFC8391.ADRS memory a;
        RFC8391.setType(a, 0);
        RFC8391.setOTSAddress(a, ots);
        RFC8391.setChainAddress(a, chainAddr);
        assertEq(impl, RFC8391.chain(X, start, steps, SEED, a));
    }

    // ── Lemma 2: randHash + adrs == Algorithm 7 (L-tree and hash-tree ADRS) ──

    function check_randHash(bytes32 L, bytes32 R, bytes32 SEED, uint32 w4, uint32 w5, uint32 w6, bool ltreeType)
        public
        view
    {
        uint32 typ = ltreeType ? 1 : 2;
        bytes32 impl = XMSS.randHash(L, R, SEED, XMSS.adrs(typ, w4, w5, w6, 0), _scratch());
        RFC8391.ADRS memory a;
        RFC8391.setType(a, typ);
        a.word[4] = w4;
        a.word[5] = w5;
        a.word[6] = w6;
        assertEq(impl, RFC8391.RAND_HASH(L, R, SEED, a));
    }

    // ── Lemma 3: wotsChecksum / wotsDigit == message encoding of Algorithm 6 ──

    /// base_w(M', 16, 64) || base_w(toByte(csum << 4, 2), 16, 3), for every M'.
    /// Message digits do not depend on the checksum argument (production passes 0);
    /// checksum digits are taken from wotsChecksum(M'), as production does.
    function check_wotsDigits(bytes32 M, uint256 anyCsum) public pure {
        uint256[] memory spec = RFC8391.wotsMsg(M);
        uint256 m = uint256(M);
        for (uint256 i = 0; i < 64; i++) {
            assert(XMSS.wotsDigit(m, anyCsum, i) == spec[i]);
        }
        uint256 csum = XMSS.wotsChecksum(m);
        for (uint256 i = 64; i < 67; i++) {
            assert(XMSS.wotsDigit(m, csum, i) == spec[i]);
        }
    }

    // ── Lemma 4: ltree == Algorithm 8 ──────────────────────────────────────

    function check_ltree(bytes32[67] memory nodes, bytes32 SEED, uint32 ltreeAddr) public view {
        bytes32[67] memory copy;
        for (uint256 i = 0; i < 67; i++) {
            copy[i] = nodes[i];
        }
        bytes32 impl = XMSS.ltree(nodes, ltreeAddr, SEED, _scratch());
        RFC8391.ADRS memory a;
        RFC8391.setType(a, 1);
        RFC8391.setLTreeAddress(a, ltreeAddr);
        assertEq(impl, RFC8391.ltree(copy, SEED, a));
    }

    // ── Lemma 5: climbStep == one iteration of Algorithm 13's loop ─────────

    /// With the loop invariant getTreeIndex() == floor(idx / 2^k) on entry to
    /// iteration k (Lemma 6), production's k-th climb step equals the RFC's.
    function check_climbStep(bytes32 node, bytes32 authK, bytes32 SEED, uint32 idx, uint8 k) public view {
        vm.assume(k < 20);
        bytes32 impl = XMSS.climbStep(node, authK, idx, k, SEED, _scratch());
        RFC8391.ADRS memory a;
        RFC8391.setType(a, 2);
        RFC8391.setTreeIndex(a, uint32(uint256(idx) >> k));
        assertEq(impl, RFC8391.rootStep(node, authK, idx, k, SEED, a));
    }

    // ── Lemma 6: Algorithm 13's tree-index update keeps floor(idx / 2^k) ───

    /// Initially (k = 0) setTreeIndex(idx_sig) gives floor(idx / 2^0). If the index is
    /// floor(idx / 2^k) before iteration k, the RFC's update (t/2 for a left node,
    /// (t-1)/2 for a right node) leaves floor(idx / 2^(k+1)). By induction the
    /// invariant holds for every k < h.
    function check_treeIndexInvariant(uint32 idx, uint8 k) public pure {
        vm.assume(k < 20);
        uint32 t = uint32(uint256(idx) >> k);
        uint32 next = ((idx / (2 ** uint256(k))) % 2 == 0) ? t / 2 : (t - 1) / 2;
        assert(next == uint32(uint256(idx) >> (k + 1)));
    }

    // ── Lemma 7: hMsg == H_msg (§4.1.9, §5.1) ──────────────────────────────

    function check_hMsg(bytes32 r, bytes32 root, uint32 idx, bytes32 M) public pure {
        assertEq(XMSS.hMsg(r, root, idx, M), RFC8391.H_msg(r, root, idx, M));
    }

    // ── Lemma 8: verify's input checks ─────────────────────────────────────

    /// Production rejects, before hashing anything, exactly the inputs outside the
    /// supported domain: zero root or SEED, h = 0 or h > 20, idx >= 2^h.
    function check_verifyRejectsOutOfDomain(bytes32 M, uint32 idx, bytes32 r, bytes32 root, bytes32 seed, uint8 h)
        public
        view
    {
        vm.assume(root == 0 || seed == 0 || h == 0 || h > 20 || uint256(idx) >= (uint256(1) << h));
        vm.assume(h <= 24);
        // Halmos needs concrete array lengths: branch once per height.
        for (uint256 c = 0; c <= 24; c++) {
            if (c == h) {
                XMSS.Signature memory sig;
                sig.leafIdx = idx;
                sig.r = r;
                sig.authPath = new bytes32[](c);
                assertFalse(XMSS.verify(M, sig, XMSS.PublicKey(root, seed)));
            }
        }
    }

    // ── Composition, checked symbolically at small height ──────────────────

    /// rootFromSig composes wotsPkFromSig, ltree and climbStep exactly as
    /// Algorithm 13 composes WOTS_pkFromSig, ltree and its loop: checked for all
    /// WOTS signatures, auth paths, SEEDs and indices at h = 2, for a fixed M'
    /// (M' fixes the 67 chain lengths; which lengths occur is covered by Lemmas 1, 3).
    function check_rootFromSig_h2(bytes32[67] memory wotsSig, bytes32 a0, bytes32 a1, bytes32 SEED, uint8 idx)
        public
        view
    {
        vm.assume(idx < 4);
        bytes32 mPrime = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0;
        XMSS.Signature memory sig;
        sig.leafIdx = idx;
        sig.authPath = new bytes32[](2);
        sig.authPath[0] = a0;
        sig.authPath[1] = a1;
        bytes32[67] memory copy;
        for (uint256 i = 0; i < 67; i++) {
            sig.wotsSig[i] = wotsSig[i];
            copy[i] = wotsSig[i];
        }
        bytes32 impl = XMSS.rootFromSig(mPrime, sig, SEED, _scratch());
        assertEq(impl, RFC8391.XMSS_rootFromSig(idx, copy, sig.authPath, mPrime, SEED));
    }

    // ── The specification against the RFC reference implementation ────────

    function _vector(string memory file, uint256 i)
        internal
        view
        returns (bytes32 M, uint32 idx, bytes32 r, bytes32[67] memory ots, bytes32[] memory auth, bytes32 root, bytes32 seed)
    {
        string memory json = vm.readFile(string.concat("test/vectors/", file));
        root = vm.parseJsonBytes32(json, ".root");
        seed = vm.parseJsonBytes32(json, ".seed");
        string memory base = string.concat(".vectors[", vm.toString(i), "]");
        idx = uint32(vm.parseJsonUint(json, string.concat(base, ".idx")));
        r = vm.parseJsonBytes32(json, string.concat(base, ".r"));
        M = vm.parseJsonBytes32(json, string.concat(base, ".msg"));
        bytes32[] memory w = vm.parseJsonBytes32Array(json, string.concat(base, ".wotsSig"));
        for (uint256 j = 0; j < 67; j++) {
            ots[j] = w[j];
        }
        auth = vm.parseJsonBytes32Array(json, string.concat(base, ".auth"));
    }

    /// The spec accepts every reference-implementation signature and rejects it for
    /// any other message, so the transcription computes what RFC 8391 computes.
    function _specAgainstReference(string memory file) internal view {
        for (uint256 i = 0; i < 4; i++) { // each vector file holds 4 signatures
            (bytes32 M, uint32 idx, bytes32 r, bytes32[67] memory ots, bytes32[] memory auth, bytes32 root, bytes32 seed)
            = _vector(file, i);
            assertTrue(RFC8391.XMSS_verify(M, idx, r, ots, auth, root, seed), "spec rejects a reference signature");
            assertFalse(
                RFC8391.XMSS_verify(bytes32(uint256(M) ^ 1), idx, r, ots, auth, root, seed),
                "spec accepts a wrong message"
            );
        }
    }

    function test_spec_referenceVectors_h4() public view {
        _specAgainstReference("xmss_h4.json");
    }

    function test_spec_referenceVectors_h10() public view {
        _specAgainstReference("xmss_h10.json");
    }

    function test_spec_referenceVectors_h20() public view {
        _specAgainstReference("xmss_h20.json");
    }
}
