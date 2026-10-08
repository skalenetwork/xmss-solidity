// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {RFC8391} from "./RFC8391.sol";

/// @title RFC 8391 XMSS^MT verification — executable specification
/// @notice A line-by-line transcription of what XMSS^MT adds to RFC8391.sol for the
///         XMSSMT-SHA2_h/d_256 parameter sets: the layer and tree address words of an
///         ADRS (§2.5), H_msg with the full index (§4.2.4), Algorithm 13 run on the
///         caller's ADRS, and Algorithm 16. Everything else (base_w, chain, WOTS+,
///         RAND_HASH, ltree, the hash functions) is RFC8391.sol, unchanged. Written for
///         fidelity to the RFC text; src/XMSSMT.sol is proven against it by Halmos in
///         XMSSMTEquivalence.t.sol, and it is checked there against the signatures of
///         py/xmssmt_ref.py, which the RFC authors' C implementation also accepts.
library RFC8391MT {
    // ── §2.5: words 0-2 of an address ─────────────────────────────────────

    function setLayerAddress(RFC8391.ADRS memory a, uint32 v) internal pure {
        a.word[0] = v;
    }

    /// The tree address is 8 bytes, words 1 (high) and 2 (low).
    function setTreeAddress(RFC8391.ADRS memory a, uint64 v) internal pure {
        a.word[1] = uint32(v >> 32);
        a.word[2] = uint32(v);
    }

    // ── §4.2.4: H_msg keyed with r || root || toByte(idx_sig, n) ───────────

    function H_msg(bytes32 r, bytes32 root, uint256 idx_sig, bytes32 M) internal pure returns (bytes32) {
        bytes memory KEY = abi.encodePacked(r, root, idx_sig); // toByte(idx_sig, 32)
        return sha256(abi.encodePacked(uint256(2), KEY, M));
    }

    // ── Algorithm 13: XMSS_rootFromSig, as Algorithm 16 calls it ───────────

    /// RFC8391.XMSS_rootFromSig, with the ADRS supplied by the caller: in XMSS^MT it
    /// arrives with the layer and tree address already set, and setType leaves those
    /// words alone.
    function XMSS_rootFromSig(
        uint32 idx_sig,
        bytes32[67] memory sig_ots,
        bytes32[] memory auth,
        bytes32 M,
        bytes32 SEED,
        RFC8391.ADRS memory a
    ) internal pure returns (bytes32 node) {
        RFC8391.setType(a, 0); // OTS hash address
        RFC8391.setOTSAddress(a, idx_sig);
        bytes32[67] memory pk_ots = RFC8391.WOTS_pkFromSig(sig_ots, M, SEED, a);
        RFC8391.setType(a, 1); // L-tree address
        RFC8391.setLTreeAddress(a, idx_sig);
        node = RFC8391.ltree(pk_ots, SEED, a);
        RFC8391.setType(a, 2); // hash tree address
        RFC8391.setTreeIndex(a, idx_sig);
        for (uint256 k = 0; k < auth.length; k++) {
            node = RFC8391.rootStep(node, auth[k], idx_sig, k, SEED, a);
        }
    }

    // ── Algorithm 16: XMSSMT_verify ────────────────────────────────────────

    /// "the b least significant bits of x"
    function lsb(uint256 x, uint256 b) internal pure returns (uint256) {
        return x % 2 ** b;
    }

    /// "the b most significant bits of x", for an xBits-bit x
    function msb(uint256 x, uint256 xBits, uint256 b) internal pure returns (uint256) {
        return x / 2 ** (xBits - b);
    }

    struct Layer {
        bytes32[67] sig_ots;
        bytes32[] auth;
    }

    /// Algorithm 16 for the parameter set XMSSMT-SHA2_h/d_256. The public key's OID
    /// fixes h and d (§4.2.6, §5.4). A signature for that set holds d reduced XMSS
    /// signatures of h/d authentication nodes each and an index below 2^h (§4.2.3),
    /// so anything else is not a signature under this key.
    function XMSSMT_verify(
        uint256 h,
        uint256 d,
        bytes32 M,
        uint256 idx_sig,
        bytes32 r,
        Layer[] memory Sig_MT,
        bytes32 root,
        bytes32 SEED
    ) internal pure returns (bool) {
        if (d == 0 || h % d != 0 || Sig_MT.length != d || idx_sig >= 2 ** h) return false;
        for (uint256 j = 0; j < d; j++) {
            if (Sig_MT[j].auth.length != h / d) return false;
        }
        RFC8391.ADRS memory a; // toByte(0, 32)

        bytes32 M_prime = H_msg(r, root, idx_sig, M);

        uint256 idx_leaf = lsb(idx_sig, h / d);
        uint256 idx_tree = msb(idx_sig, h, h - h / d);
        setLayerAddress(a, 0);
        setTreeAddress(a, uint64(idx_tree));
        bytes32 node = XMSS_rootFromSig(uint32(idx_leaf), Sig_MT[0].sig_ots, Sig_MT[0].auth, M_prime, SEED, a);
        for (uint256 j = 1; j < d; j++) {
            idx_leaf = lsb(idx_tree, h / d);
            idx_tree = msb(idx_tree, h - j * (h / d), h - (j + 1) * (h / d));
            setLayerAddress(a, uint32(j));
            setTreeAddress(a, uint64(idx_tree));
            node = XMSS_rootFromSig(uint32(idx_leaf), Sig_MT[j].sig_ots, Sig_MT[j].auth, node, SEED, a);
        }
        return node == root;
    }
}
