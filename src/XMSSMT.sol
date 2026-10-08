// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {XMSS} from "./XMSS.sol";

/// @title XMSS^MT signature verification (RFC 8391 §4.2, XMSSMT-SHA2_h/d_256 family)
/// @notice Verifies a multi-tree XMSS signature over a 32-byte message digest using the
///         SHA-256 precompile. Parameters as in `XMSS`: n = 32, w = 16, len = 67. The
///         total height h (at most 60) and the number of layers d are bound by the
///         caller, exactly as `XMSS.verify`'s four-argument form binds the tree height:
///         RFC 8391's public key carries an OID that fixes (h, d) (§4.2.6, §5.4), and
///         `XMSS.PublicKey` has no OID. The eight standardized SHA2 n = 32 sets are
///         (20, 2), (20, 4), (40, 2), (40, 4), (40, 8), (60, 3), (60, 6) and (60, 12).
/// @dev    Stateless and storage-free, like `XMSS`. Each index identifies one WOTS+
///         one-time key per layer, so callers must record every `idx` they accept and
///         refuse it again: XMSS^MT is as stateful as XMSS, only with up to 2^60 indices.
///
///         The keyed hashes (`XMSS.prf`, `XMSS.randHash`, `XMSS.fHash`), the WOTS+
///         message encoding (`XMSS.wotsDigit`, `XMSS.wotsChecksum`) and the address
///         layout (`XMSS.adrs`) are reused unchanged, so the proofs of those parts carry
///         over. What XMSS^MT adds is the layer and tree address in words 0-2 of every
///         hash address (§2.5), which `XMSS` always leaves zero; this library ORs them in
///         as a `prefix` and is otherwise a transcription of Algorithms 13 and 16.
library XMSSMT {
    /// Largest RFC 8391 total height (XMSSMT-SHA2_60/d_256): idx_sig fits in 64 bits.
    uint256 internal constant MAX_TOTAL_HEIGHT = 60;

    /// WOTS+ chains per one-time signature: XMSS.LEN, restated because Solidity only
    /// sizes a fixed array with a constant of the same contract (a test pins the two).
    uint256 internal constant LEN = 67;

    /// One layer of the hypertree: a WOTS+ signature on the message (layer 0) or on
    /// the root of the tree one layer down, and that tree's authentication path.
    struct Layer {
        bytes32[LEN] wotsSig; // 67 x 32 bytes
        bytes32[] authPath;        // h/d x 32 bytes
    }

    struct Signature {
        uint64 idx;     // idx_sig — the (one-time!) index across the whole hypertree
        bytes32 r;      // randomizer for H_msg
        Layer[] layers; // d layers, bottom (layer 0) first
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// @notice Verify an XMSS^MT signature over `messageDigest` for a key of total height
    ///         `totalHeight` and `layerCount` layers (RFC 8391 Algorithm 16).
    /// @return true iff `sig` has exactly `layerCount` layers of `totalHeight / layerCount`
    ///         authentication nodes each, an index below 2^totalHeight, and is a valid
    ///         signature on `messageDigest` under `pk`.
    function verify(
        bytes32 messageDigest,
        Signature memory sig,
        XMSS.PublicKey memory pk,
        uint256 totalHeight,
        uint256 layerCount
    ) internal view returns (bool) {
        // Same key checks as XMSS.verify: a zero SEED collapses every PRF-derived
        // key and bitmask to a function of the address alone; a zero root is never real.
        if (pk.root == bytes32(0) || pk.seed == bytes32(0)) return false;
        if (!validParams(totalHeight, layerCount)) return false;
        uint256 hp = totalHeight / layerCount;
        if (sig.layers.length != layerCount) return false;
        for (uint256 j = 0; j < layerCount; ++j) {
            if (sig.layers[j].authPath.length != hp) return false;
        }
        if (uint256(sig.idx) >= (1 << totalHeight)) return false;

        bytes32 node = hMsg(sig.r, pk.root, sig.idx, messageDigest);

        // One 160-byte hash buffer for every prf/F/H call, as in XMSS.verify.
        bytes memory scratchBuf = new bytes(160);
        uint256 scratch;
        assembly ("memory-safe") {
            scratch := add(scratchBuf, 32)
        }

        uint64 idxTree = sig.idx;
        for (uint256 j = 0; j < layerCount; ++j) {
            (uint32 idxLeaf, uint64 nextTree) = splitIndex(idxTree, hp);
            idxTree = nextTree;
            // Each layer's tree signs the node below it: M' at layer 0, a root above.
            node = rootFromSig(node, sig.layers[j], idxLeaf, prefix(uint32(j), idxTree), pk.seed, scratch);
        }
        return node == pk.root;
    }

    /// @notice Verify a signature in RFC 8391's byte encoding (§4.2.3): idx_sig as
    ///         ceil(h/8) big-endian bytes, r, then for each layer the 67 WOTS+ chains and
    ///         h/d authentication nodes. The form xmss-reference and other RFC 8391
    ///         implementations emit. Any other length is rejected, as is any index
    ///         that `decode` cannot place.
    function verifyEncoded(
        bytes32 messageDigest,
        bytes memory encoded,
        XMSS.PublicKey memory pk,
        uint256 totalHeight,
        uint256 layerCount
    ) internal view returns (bool) {
        (bool ok, Signature memory sig) = decode(encoded, totalHeight, layerCount);
        if (!ok) return false;
        return verify(messageDigest, sig, pk, totalHeight, layerCount);
    }

    /// @notice Whether (totalHeight, layerCount) is a hypertree this library verifies:
    ///         at least two layers, the layers dividing the height, each tree 1..20
    ///         high (XMSS.MAX_HEIGHT), and the total at most 60. The eight RFC 8391
    ///         SHA2 n = 32 sets all qualify; so do non-standard shapes used in tests.
    function validParams(uint256 totalHeight, uint256 layerCount) internal pure returns (bool) {
        if (layerCount < 2 || totalHeight > MAX_TOTAL_HEIGHT || totalHeight % layerCount != 0) return false;
        uint256 hp = totalHeight / layerCount;
        return hp >= 1 && hp <= XMSS.MAX_HEIGHT;
    }

    /// @notice Decode RFC 8391's XMSS^MT signature encoding into a `Signature`.
    /// @return ok false if the length is not exactly ceil(h/8) + 32 + d(67 + h/d)32
    ///         bytes or (h, d) is not valid; `sig` is then empty.
    function decode(bytes memory encoded, uint256 totalHeight, uint256 layerCount)
        internal
        pure
        returns (bool ok, Signature memory sig)
    {
        if (!validParams(totalHeight, layerCount)) return (false, sig);
        uint256 hp = totalHeight / layerCount;
        uint256 idxBytes = (totalHeight + 7) / 8;
        if (encoded.length != idxBytes + 32 + layerCount * (LEN + hp) * 32) return (false, sig);

        uint256 idx = 0;
        for (uint256 i = 0; i < idxBytes; ++i) {
            idx = (idx << 8) | uint8(encoded[i]);
        }
        sig.idx = uint64(idx); // idxBytes <= 8, so nothing is lost

        uint256 offset = idxBytes;
        sig.r = _word(encoded, offset);
        offset += 32;
        sig.layers = new Layer[](layerCount);
        for (uint256 j = 0; j < layerCount; ++j) {
            for (uint256 i = 0; i < LEN; ++i) {
                sig.layers[j].wotsSig[i] = _word(encoded, offset);
                offset += 32;
            }
            sig.layers[j].authPath = new bytes32[](hp);
            for (uint256 k = 0; k < hp; ++k) {
                sig.layers[j].authPath[k] = _word(encoded, offset);
                offset += 32;
            }
        }
        ok = true;
    }

    /// M' = H_msg(r || root || toByte(idx_sig, n), M)             (Algorithm 16; §5.1)
    ///    = SHA-256(toByte(2, 32) || r || root || toByte(idx, 32) || M)
    /// As XMSS.hMsg, with the index widened to the 60 bits XMSS^MT allows.
    function hMsg(bytes32 r, bytes32 root, uint64 idx, bytes32 m) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(uint256(2), r, root, uint256(idx), m));
    }

    /// One step of Algorithm 16's index walk: the low `hp` bits of `idxTree` are the
    /// leaf in this layer's tree, the rest is the tree's address (and the next layer's
    /// index).
    function splitIndex(uint64 idxTree, uint256 hp) internal pure returns (uint32 idxLeaf, uint64 nextTree) {
        idxLeaf = uint32(idxTree & ((uint64(1) << hp) - 1));
        nextTree = idxTree >> hp;
    }

    // ------------------------------------------------------------------
    // Algorithm 13: XMSS_rootFromSig, for the tree at (layer, tree address)
    // ------------------------------------------------------------------

    /// Words 0-2 of an RFC 8391 §2.5 address: layer (4 bytes) and tree address
    /// (8 bytes). `XMSS.adrs` fills words 3-7 and leaves these zero, so OR-ing this in
    /// gives the full address of a hash in the tree at (layer, tree).
    function prefix(uint32 layer, uint64 tree) internal pure returns (uint256) {
        return (uint256(layer) << 224) | (uint256(tree) << 160);
    }

    function rootFromSig(
        bytes32 mPrime,
        Layer memory layer,
        uint32 idxLeaf,
        uint256 pre,
        bytes32 seed,
        uint256 scratch
    ) internal view returns (bytes32) {
        bytes32[LEN] memory wotsPk = wotsPkFromSig(mPrime, layer.wotsSig, idxLeaf, pre, seed, scratch);
        bytes32 node = ltree(wotsPk, idxLeaf, pre, seed, scratch);
        for (uint256 k = 0; k < layer.authPath.length; ++k) {
            node = climbStep(node, layer.authPath[k], idxLeaf, k, pre, seed, scratch);
        }
        return node;
    }

    /// XMSS.climbStep with the layer and tree address of the tree being climbed.
    function climbStep(bytes32 node, bytes32 authNode, uint32 idx, uint256 k, uint256 pre, bytes32 seed, uint256 scratch)
        internal
        view
        returns (bytes32)
    {
        bytes32 a = bytes32(pre | uint256(XMSS.adrs(2, 0, uint32(k), uint32(idx >> (k + 1)), 0)));
        return (idx >> k) & 1 == 0
            ? XMSS.randHash(node, authNode, seed, a, scratch)
            : XMSS.randHash(authNode, node, seed, a, scratch);
    }

    /// XMSS.wotsPkFromSig with the layer and tree address.
    function wotsPkFromSig(
        bytes32 mPrime,
        bytes32[LEN] memory sigOts,
        uint32 otsAddr,
        uint256 pre,
        bytes32 seed,
        uint256 scratch
    ) internal view returns (bytes32[LEN] memory pk) {
        uint256 m = uint256(mPrime);
        uint256 csum = XMSS.wotsChecksum(m);
        for (uint256 i = 0; i < LEN; ++i) {
            uint256 d = XMSS.wotsDigit(m, csum, i);
            pk[i] = chain(sigOts[i], otsAddr, uint32(i), uint32(d), uint32(XMSS.W_MINUS_1 - d), pre, seed, scratch);
        }
    }

    /// XMSS.chain (Algorithm 2) with the layer and tree address.
    function chain(
        bytes32 x,
        uint32 otsAddr,
        uint32 chainAddr,
        uint32 start,
        uint32 steps,
        uint256 pre,
        bytes32 seed,
        uint256 scratch
    ) internal view returns (bytes32) {
        for (uint32 j = start; j < start + steps; ++j) {
            bytes32 key = XMSS.prf(seed, bytes32(pre | uint256(XMSS.adrs(0, otsAddr, chainAddr, j, 0))), scratch);
            bytes32 bm = XMSS.prf(seed, bytes32(pre | uint256(XMSS.adrs(0, otsAddr, chainAddr, j, 1))), scratch);
            x = XMSS.fHash(key, x ^ bm, scratch);
        }
        return x;
    }

    /// XMSS.ltree (Algorithm 8) with the layer and tree address.
    function ltree(bytes32[LEN] memory nodes, uint32 ltreeAddr, uint256 pre, bytes32 seed, uint256 scratch)
        internal
        view
        returns (bytes32)
    {
        uint256 l = LEN;
        uint32 height = 0;
        while (l > 1) {
            uint256 half = l >> 1;
            for (uint256 i = 0; i < half; ++i) {
                bytes32 a = bytes32(pre | uint256(XMSS.adrs(1, ltreeAddr, height, uint32(i), 0)));
                nodes[i] = XMSS.randHash(nodes[2 * i], nodes[2 * i + 1], seed, a, scratch);
            }
            if (l & 1 == 1) {
                nodes[half] = nodes[l - 1];
                l = half + 1;
            } else {
                l = half;
            }
            ++height;
        }
        return nodes[0];
    }

    function _word(bytes memory b, uint256 offset) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(add(add(b, 32), offset))
        }
    }
}
