// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title RFC 8391 XMSS verification — executable specification
/// @notice A line-by-line transcription of the RFC 8391 verification algorithms for
///         the XMSS-SHA2_h_256 parameter sets (n = 32, w = 16, len = 67), written
///         for fidelity to the RFC text rather than for gas. It is the reference the
///         production verifier (src/XMSS.sol) is proven equivalent to by Halmos in
///         XMSSEquivalence.t.sol, and it is itself checked against the RFC reference
///         implementation's signatures (test/vectors) in the same file.
///         Section and algorithm numbers refer to RFC 8391.
library RFC8391 {
    uint256 internal constant n = 32;
    uint256 internal constant w = 16;
    uint256 internal constant lg_w = 4;
    uint256 internal constant len_1 = 64; // ceil(8n / lg(w))
    uint256 internal constant len_2 = 3; //  floor(lg(len_1 * (w - 1)) / lg(w)) + 1
    uint256 internal constant len = 67;

    // ── §2.5 Hash function address scheme ──────────────────────────────────
    // Eight 32-bit words: layer, tree (2 words), type, then type-specific words,
    // then keyAndMask. Single-tree XMSS: layer = tree = 0.

    struct ADRS {
        uint32[8] word;
    }

    /// setType also zeroes the type-specific words and keyAndMask (§2.5).
    function setType(ADRS memory a, uint32 t) internal pure {
        a.word[3] = t;
        a.word[4] = 0;
        a.word[5] = 0;
        a.word[6] = 0;
        a.word[7] = 0;
    }

    function setOTSAddress(ADRS memory a, uint32 v) internal pure { a.word[4] = v; }
    function setChainAddress(ADRS memory a, uint32 v) internal pure { a.word[5] = v; }
    function setHashAddress(ADRS memory a, uint32 v) internal pure { a.word[6] = v; }
    function setLTreeAddress(ADRS memory a, uint32 v) internal pure { a.word[4] = v; }
    function setTreeHeight(ADRS memory a, uint32 v) internal pure { a.word[5] = v; }
    function setTreeIndex(ADRS memory a, uint32 v) internal pure { a.word[6] = v; }
    function setKeyAndMask(ADRS memory a, uint32 v) internal pure { a.word[7] = v; }
    function getTreeHeight(ADRS memory a) internal pure returns (uint32) { return a.word[5]; }

    /// §2.4 toByte / §2.5: an ADRS is serialised as its eight words, big-endian.
    function toBytes(ADRS memory a) internal pure returns (bytes32) {
        return bytes32(
            abi.encodePacked(
                a.word[0], a.word[1], a.word[2], a.word[3], a.word[4], a.word[5], a.word[6], a.word[7]
            )
        );
    }

    // ── §5.1 Hash functions, SHA2 instantiation (n = 32) ───────────────────
    // Each is SHA-256 over toByte(domain, 32) || KEY || M.

    function F(bytes32 KEY, bytes32 M) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(uint256(0), KEY, M));
    }

    function H(bytes32 KEY, bytes32 M0, bytes32 M1) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(uint256(1), KEY, M0, M1));
    }

    /// H_msg(KEY, M) with KEY = r || getRoot(PK) || toByte(idx_sig, n)   (Algorithm 14, §4.1.10)
    function H_msg(bytes32 r, bytes32 root, uint32 idx_sig, bytes32 M) internal pure returns (bytes32) {
        bytes memory KEY = abi.encodePacked(r, root, uint256(idx_sig));
        return sha256(abi.encodePacked(uint256(2), KEY, M));
    }

    function PRF(bytes32 SEED, ADRS memory a) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(uint256(3), SEED, toBytes(a)));
    }

    // ── Algorithm 1: base_w ────────────────────────────────────────────────

    function base_w(bytes memory X, uint256 out_len) internal pure returns (uint256[] memory basew) {
        basew = new uint256[](out_len);
        uint256 in_ = 0;
        uint256 total = 0;
        uint256 bits = 0;
        for (uint256 consumed = 0; consumed < out_len; consumed++) {
            if (bits == 0) {
                total = uint8(X[in_]);
                in_++;
                bits += 8;
            }
            bits -= lg_w;
            basew[consumed] = (total >> bits) & (w - 1);
        }
    }

    // ── Algorithm 2: chain ─────────────────────────────────────────────────

    function chain(bytes32 X, uint256 i, uint256 s, bytes32 SEED, ADRS memory a) internal pure returns (bytes32) {
        if (s == 0) return X;
        require(i + s <= w - 1, "NULL");
        bytes32 tmp = chain(X, i, s - 1, SEED, a);
        setHashAddress(a, uint32(i + s - 1));
        setKeyAndMask(a, 0);
        bytes32 KEY = PRF(SEED, a);
        setKeyAndMask(a, 1);
        bytes32 BM = PRF(SEED, a);
        tmp = F(KEY, tmp ^ BM);
        return tmp;
    }

    // ── Algorithm 6 (message encoding shared with Algorithm 5) ─────────────

    /// The len base-w digits of M: base_w(M, len_1) || base_w(toByte(csum', ...), len_2).
    function wotsMsg(bytes32 M) internal pure returns (uint256[] memory msg_) {
        uint256[] memory m1 = base_w(abi.encodePacked(M), len_1);
        uint256 csum = 0;
        for (uint256 i = 0; i < len_1; i++) {
            csum = csum + w - 1 - m1[i];
        }
        csum = csum << (8 - ((len_2 * lg_w) % 8));
        uint256 len_2_bytes = (len_2 * lg_w + 7) / 8; // ceil((len_2 * lg(w)) / 8)
        bytes memory cb = new bytes(len_2_bytes); //     toByte(csum, len_2_bytes)
        for (uint256 i = 0; i < len_2_bytes; i++) {
            cb[i] = bytes1(uint8(csum >> (8 * (len_2_bytes - 1 - i))));
        }
        uint256[] memory m2 = base_w(cb, len_2);
        msg_ = new uint256[](len);
        for (uint256 i = 0; i < len_1; i++) msg_[i] = m1[i];
        for (uint256 i = 0; i < len_2; i++) msg_[len_1 + i] = m2[i];
    }

    /// Algorithm 6: WOTS_pkFromSig (ADRS must be an OTS address with the OTS address set).
    function WOTS_pkFromSig(bytes32[67] memory sig, bytes32 M, bytes32 SEED, ADRS memory a)
        internal
        pure
        returns (bytes32[67] memory tmp_pk)
    {
        uint256[] memory msg_ = wotsMsg(M);
        for (uint256 i = 0; i < len; i++) {
            setChainAddress(a, uint32(i));
            tmp_pk[i] = chain(sig[i], msg_[i], w - 1 - msg_[i], SEED, a);
        }
    }

    // ── Algorithm 7: RAND_HASH ─────────────────────────────────────────────

    function RAND_HASH(bytes32 LEFT, bytes32 RIGHT, bytes32 SEED, ADRS memory a) internal pure returns (bytes32) {
        setKeyAndMask(a, 0);
        bytes32 KEY = PRF(SEED, a);
        setKeyAndMask(a, 1);
        bytes32 BM_0 = PRF(SEED, a);
        setKeyAndMask(a, 2);
        bytes32 BM_1 = PRF(SEED, a);
        return H(KEY, LEFT ^ BM_0, RIGHT ^ BM_1);
    }

    // ── Algorithm 8: ltree ─────────────────────────────────────────────────

    function ltree(bytes32[67] memory pk, bytes32 SEED, ADRS memory a) internal pure returns (bytes32) {
        uint256 len_ = len;
        setTreeHeight(a, 0);
        while (len_ > 1) {
            for (uint256 i = 0; i < len_ / 2; i++) {
                setTreeIndex(a, uint32(i));
                pk[i] = RAND_HASH(pk[2 * i], pk[2 * i + 1], SEED, a);
            }
            if (len_ % 2 == 1) {
                pk[len_ / 2] = pk[len_ - 1];
            }
            len_ = (len_ + 1) / 2; // ceil(len' / 2)
            setTreeHeight(a, getTreeHeight(a) + 1);
        }
        return pk[0];
    }

    // ── Algorithm 13: XMSS_rootFromSig ─────────────────────────────────────

    /// One iteration k of Algorithm 13's loop, verbatim (ADRS of type 2; on entry
    /// the tree index holds what the previous iteration left there).
    function rootStep(bytes32 node0, bytes32 authK, uint256 idx_sig, uint256 k, bytes32 SEED, ADRS memory a)
        internal
        pure
        returns (bytes32 node1)
    {
        setTreeHeight(a, uint32(k));
        if ((idx_sig / (2 ** k)) % 2 == 0) {
            setTreeIndex(a, a.word[6] / 2);
            node1 = RAND_HASH(node0, authK, SEED, a);
        } else {
            setTreeIndex(a, (a.word[6] - 1) / 2);
            node1 = RAND_HASH(authK, node0, SEED, a);
        }
    }

    function XMSS_rootFromSig(
        uint32 idx_sig,
        bytes32[67] memory sig_ots,
        bytes32[] memory auth,
        bytes32 M,
        bytes32 SEED
    ) internal pure returns (bytes32 node) {
        ADRS memory a; // layer 0, tree 0
        setType(a, 0); // OTS hash address
        setOTSAddress(a, idx_sig);
        bytes32[67] memory pk_ots = WOTS_pkFromSig(sig_ots, M, SEED, a);
        setType(a, 1); // L-tree address
        setLTreeAddress(a, idx_sig);
        node = ltree(pk_ots, SEED, a);
        setType(a, 2); // hash tree address
        setTreeIndex(a, idx_sig);
        for (uint256 k = 0; k < auth.length; k++) {
            node = rootStep(node, auth[k], idx_sig, k, SEED, a);
        }
    }

    // ── Algorithm 14: XMSS_verify ──────────────────────────────────────────

    /// Algorithm 14 for the parameter set XMSS-SHA2_h_256. The public key's OID fixes
    /// h (§4.1.7, §5.3). A signature for that set holds exactly h authentication nodes
    /// and an index below 2^h (§4.1.8), so anything else is not a signature under this
    /// key. The standardized sets have h = 10, 16 or 20; the reference implementation
    /// also uses h = 4 for testing.
    function XMSS_verify(
        uint256 h,
        bytes32 M,
        uint32 idx_sig,
        bytes32 r,
        bytes32[67] memory sig_ots,
        bytes32[] memory auth,
        bytes32 root,
        bytes32 SEED
    ) internal pure returns (bool) {
        if (auth.length != h || uint256(idx_sig) >= 2 ** h) return false;
        bytes32 M_prime = H_msg(r, root, idx_sig, M);
        return XMSS_rootFromSig(idx_sig, sig_ots, auth, M_prime, SEED) == root;
    }
}
